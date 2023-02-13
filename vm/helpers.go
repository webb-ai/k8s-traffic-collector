package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/utils"
	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

const HttpRequestTimeoutSecond = 5

func defineWebhook(o *otto.Otto, scriptIndex int64, license bool) {
	helperName := "webhook"
	err := o.Set(helperName, func(call otto.FunctionCall) otto.Value {
		returnValue := otto.UndefinedValue()

		if protectLicense(helperName, scriptIndex, license) {
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
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

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

func definePass(o *otto.Otto, scriptIndex int64) {
	err := o.Set("pass", func(call otto.FunctionCall) otto.Value {
		obj := call.Argument(0).Object()

		err := obj.Set("passed", true)
		if err != nil {
			SendLogError(scriptIndex, err.Error())
		}

		return obj.Value()
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineFail(o *otto.Otto, scriptIndex int64) {
	err := o.Set("fail", func(call otto.FunctionCall) otto.Value {
		obj := call.Argument(0).Object()

		err := obj.Set("failed", true)
		if err != nil {
			SendLogError(scriptIndex, err.Error())
		}

		return obj.Value()
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineSlack(o *otto.Otto, scriptIndex int64, license bool) {
	helperName := "slack"
	err := o.Set(helperName, func(call otto.FunctionCall) otto.Value {
		returnValue := otto.UndefinedValue()

		if protectLicense(helperName, scriptIndex, license) {
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
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineInfluxDB(o *otto.Otto, scriptIndex int64, license bool) {
	helperName := "influxdb"
	err := o.Set(helperName, func(call otto.FunctionCall) otto.Value {
		returnValue := otto.UndefinedValue()

		if protectLicense(helperName, scriptIndex, license) {
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
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineS3(o *otto.Otto, scriptIndex int64, license bool, node string, ip string) {
	helperName := "s3"
	err := o.Set(helperName, func(call otto.FunctionCall) otto.Value {
		returnValue := otto.UndefinedValue()

		if protectLicense(helperName, scriptIndex, license) {
			return returnValue
		}

		region := call.Argument(0).String()
		keyID := call.Argument(1).String()
		accessKey := call.Argument(2).String()
		bucket := call.Argument(3).String()
		id := call.Argument(4).String()

		pcapPath := misc.GetPcapPath(id)

		file, err := os.Open(pcapPath)
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

		input := &s3manager.UploadInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String(fmt.Sprintf("%s_%s_%s", node, ip, id)),
			Body:        file,
			ContentType: aws.String(contentType),
		}
		_, err = uploader.UploadWithContext(context.Background(), input)
		if err != nil {
			SendLogError(scriptIndex, err.Error())
			return returnValue
		}

		return returnValue
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineNameResolutionHistory(o *otto.Otto, scriptIndex int64) {
	err := o.Set("nameResolutionHistory", func(call otto.FunctionCall) otto.Value {
		m := resolver.K8sResolver.GetDumpNameResolutionHistoryMapStringKeys()

		o := otto.New()
		value, err := o.ToValue(m)
		if err != nil {
			SendLogError(scriptIndex, err.Error())
			return otto.UndefinedValue()
		}

		return value
	})

	if err != nil {
		SendLogError(scriptIndex, err.Error())
	}
}

func defineHelpers(otto *otto.Otto, scriptIndex int64, license bool, node string, ip string) {
	defineWebhook(otto, scriptIndex, license)
	defineConsole(otto, scriptIndex)
	definePass(otto, scriptIndex)
	defineFail(otto, scriptIndex)
	defineSlack(otto, scriptIndex, license)
	defineInfluxDB(otto, scriptIndex, license)
	defineS3(otto, scriptIndex, license, node, ip)
	defineNameResolutionHistory(otto, scriptIndex)
}
