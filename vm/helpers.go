package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/mergecap"
	"github.com/kubeshark/worker/utils"
	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

const HttpRequestTimeoutSecond = 5

func defineConsole(o *otto.Otto, scriptIndex int64) {
	err := o.Set("console", map[string]interface{}{
		"log": func(call otto.FunctionCall) otto.Value {
			SendLog(scriptIndex, ArgumentListToString(call.ArgumentList))

			return otto.UndefinedValue()
		},
		"error": func(call otto.FunctionCall) otto.Value {
			SendLogError(scriptIndex, ArgumentListToString(call.ArgumentList))

			return otto.UndefinedValue()
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineTest(o *otto.Otto, scriptIndex int64) {
	err := o.Set("test", map[string]interface{}{
		"pass": func(call otto.FunctionCall) otto.Value {
			obj := call.Argument(0).Object()

			err := obj.Set("passed", true)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
			}

			return obj.Value()
		},
		"fail": func(call otto.FunctionCall) otto.Value {
			obj := call.Argument(0).Object()

			err := obj.Set("failed", true)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
			}

			return obj.Value()
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineVendor(o *otto.Otto, scriptIndex int64, license bool, node string, ip string) {
	err := o.Set("vendor", map[string]interface{}{
		"webhook": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("webhook", scriptIndex, license) {
				return returnValue
			}

			method := call.Argument(0).String()
			url := call.Argument(1).String()
			body := call.Argument(2).String()

			client := &http.Client{}
			req, err := http.NewRequest(method, url, strings.NewReader(body))
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return returnValue
			}

			_, err = client.Do(req)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return returnValue
			}

			return returnValue
		},
		"slack": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("slack", scriptIndex, license) {
				return returnValue
			}

			token := call.Argument(0).String()
			channelId := call.Argument(1).String()
			pretext := call.Argument(2).String()
			text := call.Argument(3).String()
			color := call.Argument(4).String()

			client := slack.New(token, slack.OptionDebug(false))

			attachment := slack.Attachment{
				Pretext: pretext,
				Text:    text,
				Color:   color,
				Fields: []slack.AttachmentField{
					{
						Title: "Timestamp",
						Value: time.Now().String(),
					},
				},
			}

			_, timestamp, err := client.PostMessage(
				channelId,
				slack.MsgOptionAttachments(attachment),
			)

			if err != nil {
				SendLogError(scriptIndex, err.Error())
			} else {
				secs, nanos, err := utils.ParseSeconds(timestamp)
				if err != nil {
					log.Error().Err(err).Send()
					return returnValue
				}
				SendLog(scriptIndex, fmt.Sprintf("Message sent to Slack channel: %s at %s", channelId, time.Unix(secs, nanos).UTC()))
			}

			return returnValue
		},
		"influxdb": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("influxdb", scriptIndex, license) {
				return returnValue
			}

			url := call.Argument(0).String()
			token := call.Argument(1).String()
			measurement := call.Argument(2).String()
			organization := call.Argument(3).String()
			bucket := call.Argument(4).String()

			bytes, err := call.Argument(5).Object().MarshalJSON()
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return returnValue
			}

			var object map[string]interface{}
			if err := json.Unmarshal(bytes, &object); err != nil {
				SendLogError(scriptIndex, err.Error())
				return returnValue
			}

			client := influxdb2.NewClientWithOptions(
				url,
				token,
				influxdb2.DefaultOptions().SetBatchSize(20),
			)
			defer client.Close()

			writeAPI := client.WriteAPI(organization, bucket)

			p := influxdb2.NewPoint(
				measurement,
				nil,
				object,
				time.Now(),
			)

			writeAPI.WritePoint(p)

			writeAPI.Flush()

			return returnValue
		},
		"s3": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("s3", scriptIndex, license) {
				return returnValue
			}

			region := call.Argument(0).String()
			keyID := call.Argument(1).String()
			accessKey := call.Argument(2).String()
			bucket := call.Argument(3).String()
			path := call.Argument(4).String()

			file, err := os.Open(misc.GetDataPath(path))
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return returnValue
			}

			contentType, err := misc.GetFileContentType(file)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return returnValue
			}

			s3Config := &aws.Config{
				Region:      aws.String(region),
				Credentials: credentials.NewStaticCredentials(keyID, accessKey, ""),
			}

			s3Session, err := session.NewSession(s3Config)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return returnValue
			}

			uploader := s3manager.NewUploader(s3Session)

			key := fmt.Sprintf("%s/%s/%s", node, ip, filepath.Base(path))

			input := &s3manager.UploadInput{
				Bucket:      aws.String(bucket),
				Key:         aws.String(key),
				Body:        file,
				ContentType: aws.String(contentType),
			}
			_, err = uploader.UploadWithContext(context.Background(), input)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return returnValue
			}

			SendLog(scriptIndex, fmt.Sprintf("Uploaded %s file to AWS S3 bucket: %s", key, bucket))

			return returnValue
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func definePcap(o *otto.Otto, scriptIndex int64) {
	err := o.Set("pcap", map[string]interface{}{
		"nameResolutionHistory": func(call otto.FunctionCall) otto.Value {
			m := resolver.K8sResolver.GetDumpNameResolutionHistoryMapStringKeys()

			o := otto.New()
			value, err := o.ToValue(m)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return otto.UndefinedValue()
			}

			return value
		},
		"snapshot": func(call otto.FunctionCall) otto.Value {
			pcapsDir := misc.GetPcapsDir()
			pcapFiles, err := os.ReadDir(pcapsDir)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return otto.UndefinedValue()
			}

			outFile, err := os.CreateTemp(pcapsDir, "mergecap")
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return otto.UndefinedValue()
			}
			defer outFile.Close()

			err = mergecap.Mergecap(pcapFiles, "", []string{}, outFile)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return otto.UndefinedValue()
			}

			value, err := otto.ToValue(outFile.Name())
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return otto.UndefinedValue()
			}

			return value
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineFile(o *otto.Otto, scriptIndex int64) {
	err := o.Set("file", map[string]interface{}{
		"write": func(call otto.FunctionCall) otto.Value {
			path := call.Argument(0).String()
			content := call.Argument(1).String()

			err := os.WriteFile(misc.GetDataPath(path), []byte(content), 0644)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
			}

			return otto.UndefinedValue()
		},
		"append": func(call otto.FunctionCall) otto.Value {
			path := call.Argument(0).String()
			content := call.Argument(1).String()

			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				return otto.UndefinedValue()
			}
			defer f.Close()

			if _, err := f.WriteString(content); err != nil {
				SendLogError(scriptIndex, err.Error())
			}

			return otto.UndefinedValue()
		},
		"move": func(call otto.FunctionCall) otto.Value {
			oldPath := call.Argument(0).String()
			newPath := call.Argument(1).String()

			err := os.Rename(misc.GetDataPath(oldPath), misc.GetDataPath(newPath))
			if err != nil {
				SendLogError(scriptIndex, err.Error())
			}

			return otto.UndefinedValue()
		},
		"delete": func(call otto.FunctionCall) otto.Value {
			path := call.Argument(0).String()

			err := os.Remove(misc.GetDataPath(path))
			if err != nil {
				SendLogError(scriptIndex, err.Error())
			}

			return otto.UndefinedValue()
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineHelpers(otto *otto.Otto, scriptIndex int64, license bool, node string, ip string) {
	defineConsole(otto, scriptIndex)
	defineTest(otto, scriptIndex)
	defineVendor(otto, scriptIndex, license, node, ip)
	definePcap(otto, scriptIndex)
	defineFile(otto, scriptIndex)
}
