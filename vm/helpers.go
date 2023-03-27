package vm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/elastic/go-elasticsearch/esapi"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/go-co-op/gocron"
	"github.com/google/uuid"
	"github.com/grassmudhorses/vader-go/lexicon"
	"github.com/grassmudhorses/vader-go/sentitext"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/kubeshark/base/pkg/languages/kfl"
	openai "github.com/kubeshark/openai-go"
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
				return throwError(call, err)
			}

			return obj.Value()
		},
		"fail": func(call otto.FunctionCall) otto.Value {
			obj := call.Argument(0).Object()

			err := obj.Set("failed", true)
			if err != nil {
				return throwError(call, err)
			}

			return obj.Value()
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineVendor(o *otto.Otto, scriptIndex int64, node string, ip string) {
	err := o.Set("vendor", map[string]interface{}{
		"webhook": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("webhook", scriptIndex) {
				return returnValue
			}

			method := call.Argument(0).String()
			url := call.Argument(1).String()
			body := call.Argument(2).String()

			client := &http.Client{}
			req, err := http.NewRequest(method, url, strings.NewReader(body))
			if err != nil {
				return throwError(call, err)
			}

			_, err = client.Do(req)
			if err != nil {
				return throwError(call, err)
			}

			return returnValue
		},
		"slack": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("slack", scriptIndex) {
				return returnValue
			}

			webhookUrl := call.Argument(0).String()
			pretext := call.Argument(1).String()
			text := call.Argument(2).String()
			color := call.Argument(3).String()

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

			attachmentMarshalled, err := json.Marshal(attachment)
			if err != nil {
				return throwError(call, err)
			}

			client := &http.Client{}
			req, err := http.NewRequest("POST", webhookUrl, bytes.NewBuffer(attachmentMarshalled))
			if err != nil {
				return throwError(call, err)
			}

			_, err = client.Do(req)
			if err != nil {
				return throwError(call, err)
			}

			return returnValue
		},
		"slackBot": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("slackBot", scriptIndex) {
				return returnValue
			}

			token := call.Argument(0).String()
			channelId := call.Argument(1).String()
			pretext := call.Argument(2).String()
			text := call.Argument(3).String()
			color := call.Argument(4).String()

			var fields []slack.AttachmentField
			if len(call.ArgumentList) > 5 {

				bytes, err := call.Argument(5).Object().MarshalJSON()
				if err != nil {
					return throwError(call, err)
				}

				var fieldsMap map[string]string
				if err := json.Unmarshal(bytes, &fieldsMap); err != nil {
					return throwError(call, err)
				}

				for key, value := range fieldsMap {
					fields = append(fields, slack.AttachmentField{
						Title: key,
						Value: value,
					})
				}
			}
			fields = append(fields, slack.AttachmentField{
				Title: "Timestamp",
				Value: time.Now().String(),
			})

			client := slack.New(token, slack.OptionDebug(false))

			var files []*slack.File
			if len(call.ArgumentList) > 6 {

				bytes, err := call.Argument(6).Object().MarshalJSON()
				if err != nil {
					return throwError(call, err)
				}

				var filesMap map[string]string
				if err := json.Unmarshal(bytes, &filesMap); err != nil {
					return throwError(call, err)
				}

				// Upload files
				for name, path := range filesMap {
					file, err := client.UploadFile(slack.FileUploadParameters{File: misc.GetDataPath(path), Filename: name})
					if err != nil {
						return throwError(call, err)
					}

					files = append(files, file)
				}
			}

			var options []slack.MsgOption
			options = append(options, slack.MsgOptionAttachments(
				slack.Attachment{
					Pretext: pretext,
					Text:    text,
					Color:   color,
					Fields:  fields,
				},
			))

			_, timestamp, err := client.PostMessage(
				channelId,
				options...,
			)

			// Send message
			if err != nil {
				return throwError(call, err)
			} else {
				secs, nanos, err := utils.ParseSeconds(timestamp)
				if err != nil {
					log.Error().Err(err).Send()
					return returnValue
				}
				SendLog(scriptIndex, fmt.Sprintf("Message sent to Slack channel: %s at %s", channelId, time.Unix(secs, nanos).UTC()))
			}

			// Share files
			for _, file := range files {
				if file != nil {
					_, err = client.ShareRemoteFile([]string{channelId}, file.ID, file.ID)
					if err != nil {
						return throwError(call, err)
					}
					SendLog(scriptIndex, fmt.Sprintf("Shared file: %s to Slack channel: %s", file.Name, channelId))
				}
			}

			return returnValue
		},
		"influxdb": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("influxdb", scriptIndex) {
				return returnValue
			}

			url := call.Argument(0).String()
			token := call.Argument(1).String()
			organization := call.Argument(2).String()
			bucket := call.Argument(3).String()
			measurement := call.Argument(4).String()

			bytes, err := call.Argument(5).Object().MarshalJSON()
			if err != nil {
				return throwError(call, err)
			}

			var fields map[string]interface{}
			if err := json.Unmarshal(bytes, &fields); err != nil {
				return throwError(call, err)
			}

			var tags map[string]string
			if len(call.ArgumentList) > 6 {
				bytes, err = call.Argument(6).Object().MarshalJSON()
				if err != nil {
					return throwError(call, err)
				}

				if err := json.Unmarshal(bytes, &tags); err != nil {
					return throwError(call, err)
				}
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
				tags,
				fields,
				time.Now(),
			)

			writeAPI.WritePoint(p)

			writeAPI.Flush()

			return returnValue
		},
		"elastic": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("elastic", scriptIndex) {
				return returnValue
			}

			url := call.Argument(0).String()
			index := call.Argument(1).String()

			username := call.Argument(3).String()
			if len(call.ArgumentList) < 4 {
				username = ""
			}
			password := call.Argument(4).String()
			if len(call.ArgumentList) < 5 {
				password = ""
			}

			cloudID := call.Argument(5).String()
			if len(call.ArgumentList) < 6 {
				cloudID = ""
			}
			apiKey := call.Argument(6).String()
			if len(call.ArgumentList) < 7 {
				apiKey = ""
			}
			serviceToken := call.Argument(7).String()
			if len(call.ArgumentList) < 8 {
				serviceToken = ""
			}
			certificateFingerprint := call.Argument(8).String()
			if len(call.ArgumentList) < 9 {
				certificateFingerprint = ""
			}

			bytes, err := call.Argument(2).Object().MarshalJSON()
			if err != nil {
				return throwError(call, err)
			}

			ctx := context.Background()

			addresses := []string{}
			if url != "" {
				addresses = []string{
					url,
				}
			}

			cfg := elasticsearch.Config{
				Addresses:              addresses,
				Username:               username,
				Password:               password,
				CloudID:                cloudID,
				APIKey:                 apiKey,
				ServiceToken:           serviceToken,
				CertificateFingerprint: certificateFingerprint,
			}

			client, err := elasticsearch.NewClient(cfg)
			if err != nil {
				return throwError(call, err)
			}

			documentID := uuid.New().String()

			req := esapi.IndexRequest{
				Index:      index,
				DocumentID: documentID,
				Body:       strings.NewReader(string(bytes)),
				Refresh:    "true",
			}

			res, err := req.Do(ctx, client)
			if err != nil {
				return throwError(call, err)
			}
			defer res.Body.Close()

			if res.IsError() {
				return throwError(call, errors.New(res.String()))
			}

			value, err := otto.ToValue(documentID)
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
		"s3": map[string]interface{}{
			"put": func(call otto.FunctionCall) otto.Value {
				returnValue := otto.UndefinedValue()

				if protectLicense("s3", scriptIndex) {
					return returnValue
				}

				region := call.Argument(0).String()
				keyID := call.Argument(1).String()
				accessKey := call.Argument(2).String()
				bucket := call.Argument(3).String()
				path := call.Argument(4).String()

				file, err := os.Open(misc.GetDataPath(path))
				if err != nil {
					return throwError(call, err)
				}

				contentType, err := misc.GetFileContentType(file)
				if err != nil {
					return throwError(call, err)
				}

				s3Config := &aws.Config{
					Region:      aws.String(region),
					Credentials: credentials.NewStaticCredentials(keyID, accessKey, ""),
				}

				s3Session, err := session.NewSession(s3Config)
				if err != nil {
					return throwError(call, err)
				}

				uploader := s3manager.NewUploader(s3Session)

				key := fmt.Sprintf("%s_%s/%s", node, ip, filepath.Base(path))

				input := &s3manager.UploadInput{
					Bucket:      aws.String(bucket),
					Key:         aws.String(key),
					Body:        file,
					ContentType: aws.String(contentType),
				}
				output, err := uploader.UploadWithContext(context.Background(), input)
				if err != nil {
					return throwError(call, err)
				}

				SendLog(scriptIndex, fmt.Sprintf("Uploaded %s file to AWS S3 bucket: %s", key, bucket))

				value, err := otto.ToValue(output.Location)
				if err != nil {
					return throwError(call, err)
				}

				return value
			},
			"clear": func(call otto.FunctionCall) otto.Value {
				returnValue := otto.UndefinedValue()

				if protectLicense("s3", scriptIndex) {
					return returnValue
				}

				region := call.Argument(0).String()
				keyID := call.Argument(1).String()
				accessKey := call.Argument(2).String()
				bucket := call.Argument(3).String()

				s3Config := &aws.Config{
					Region:      aws.String(region),
					Credentials: credentials.NewStaticCredentials(keyID, accessKey, ""),
				}

				s3Session, err := session.NewSession(s3Config)
				if err != nil {
					return throwError(call, err)
				}

				s3client := s3.New(s3Session)

				folder := fmt.Sprintf("%s_%s", node, ip)

				iter := s3manager.NewDeleteListIterator(s3client, &s3.ListObjectsInput{
					Bucket: aws.String(bucket),
					Prefix: aws.String(folder),
				})

				if err := s3manager.NewBatchDeleteWithClient(s3client).Delete(context.Background(), iter); err != nil {
					return throwError(call, err)
				}

				SendLog(scriptIndex, fmt.Sprintf("Deleted all files under %s in AWS S3 bucket: %s", folder, bucket))

				return returnValue
			},
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
				return throwError(call, err)
			}

			return value
		},
		"snapshot": func(call otto.FunctionCall) otto.Value {
			selectedPcaps := []string{}
			if len(call.ArgumentList) > 0 {
				// The final element of the PCAP paths (the base name), not the entire path
				_selectedPcaps, err := call.Argument(0).Export()
				if err != nil {
					return throwError(call, err)
				}

				var ok bool
				selectedPcaps, ok = _selectedPcaps.([]string)
				if !ok {
					selectedPcaps = []string{}
				}
			}

			pcapsDir := misc.GetPcapsDir()
			if len(call.ArgumentList) > 1 {
				pcapsDir = misc.GetDataPath(call.Argument(1).String())
			}

			pcapFiles, err := os.ReadDir(pcapsDir)
			if err != nil {
				return throwError(call, err)
			}

			outFile, err := os.Create(fmt.Sprintf("%s/%d.pcap", misc.GetDataDir(), time.Now().Unix()))
			if err != nil {
				return throwError(call, err)
			}
			defer outFile.Close()

			err = mergecap.Mergecap(pcapFiles, "", selectedPcaps, outFile)
			if err != nil {
				return throwError(call, err)
			}

			value, err := otto.ToValue(misc.RemoveDataDir(outFile.Name()))
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
		"path": func(call otto.FunctionCall) otto.Value {
			pcapPath := misc.GetPcapPath(call.Argument(0).String())

			value, err := otto.ToValue(misc.RemoveDataDir(pcapPath))
			if err != nil {
				return throwError(call, err)
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
				return throwError(call, err)
			}

			return otto.UndefinedValue()
		},
		"append": func(call otto.FunctionCall) otto.Value {
			path := call.Argument(0).String()
			content := call.Argument(1).String()

			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return throwError(call, err)
			}
			defer f.Close()

			if _, err := f.WriteString(content); err != nil {
				return throwError(call, err)
			}

			return otto.UndefinedValue()
		},
		"move": func(call otto.FunctionCall) otto.Value {
			oldPath := misc.GetDataPath(call.Argument(0).String())
			newPath := misc.GetDataPath(call.Argument(1).String())

			if isDirectory(newPath) {
				newPath = filepath.Join(newPath, filepath.Base(oldPath))
			}

			err := os.Rename(oldPath, newPath)
			if err != nil {
				return throwError(call, err)
			}

			return otto.UndefinedValue()
		},
		"copy": func(call otto.FunctionCall) otto.Value {
			srcPath := misc.GetDataPath(call.Argument(0).String())
			dstPath := misc.GetDataPath(call.Argument(1).String())

			err := CopyFile(srcPath, dstPath)
			if err != nil {
				return throwError(call, err)
			}

			return otto.UndefinedValue()
		},
		"delete": func(call otto.FunctionCall) otto.Value {
			path := misc.GetDataPath(call.Argument(0).String())

			err := os.RemoveAll(path)
			if err != nil {
				return throwError(call, err)
			}

			return otto.UndefinedValue()
		},
		"mkdir": func(call otto.FunctionCall) otto.Value {
			path := misc.GetDataPath(call.Argument(0).String())

			err := os.MkdirAll(path, os.ModePerm)
			if err != nil {
				return throwError(call, err)
			}

			return otto.UndefinedValue()
		},
		"mkdirTemp": func(call otto.FunctionCall) otto.Value {
			name := ""
			dir := misc.GetDataDir()

			if len(call.ArgumentList) > 0 {
				name = call.Argument(0).String()
			}

			if len(call.ArgumentList) > 1 {
				dir = misc.GetDataPath(call.Argument(1).String())
			}

			dirPath, err := os.MkdirTemp(dir, name)
			if err != nil {
				return throwError(call, err)
			}

			value, err := otto.ToValue(misc.RemoveDataDir(dirPath))
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
		"temp": func(call otto.FunctionCall) otto.Value {
			name := call.Argument(0).String()
			dir := misc.GetDataPath(call.Argument(1).String())
			extension := call.Argument(2).String()

			if extension == "" {
				extension = "txt"
			}

			f, err := os.CreateTemp(dir, fmt.Sprintf("%s*.%s", name, extension))
			if err != nil {
				return throwError(call, err)
			}
			defer f.Close()

			value, err := otto.ToValue(misc.RemoveDataDir(f.Name()))
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
		"tar": func(call otto.FunctionCall) otto.Value {
			dir := misc.GetDataPath(call.Argument(0).String())

			zipName := fmt.Sprintf("kubeshark_%d.tar.gz", time.Now().Unix())
			zipPath := misc.GetDataPath(zipName)
			var file *os.File
			file, err := os.Create(zipPath)
			if err != nil {
				return throwError(call, err)
			}
			defer file.Close()

			gzipWriter := gzip.NewWriter(file)
			defer gzipWriter.Close()

			tarWriter := tar.NewWriter(gzipWriter)
			defer tarWriter.Close()

			walker := func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()

				stat, err := file.Stat()
				if err != nil {
					return err
				}

				header := &tar.Header{
					Name:    path[len(dir)+1:],
					Size:    stat.Size(),
					Mode:    int64(stat.Mode()),
					ModTime: stat.ModTime(),
				}

				err = tarWriter.WriteHeader(header)
				if err != nil {
					return err
				}

				_, err = io.Copy(tarWriter, file)
				if err != nil {
					return err
				}

				return nil
			}

			err = filepath.Walk(dir, walker)
			if err != nil {
				return throwError(call, err)
			}

			value, err := otto.ToValue(misc.RemoveDataDir(zipPath))
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineJobs(o *otto.Otto, scriptIndex int64, v *VM) {
	err := o.Set("jobs", map[string]interface{}{
		"schedule": func(call otto.FunctionCall) otto.Value {
			var argumentList []otto.Value
			if len(call.ArgumentList) > 4 {
				argumentList = call.ArgumentList[4:]
			}

			tag := FormatJobTag(call.Argument(0).String())
			cron := call.Argument(1).String()
			limit, err := call.Argument(3).ToInteger()
			if err != nil {
				SendLogError(scriptIndex, err.Error())
				limit = 0
			}
			task := func() {
				v.Lock()
				_, err := call.Argument(2).Call(call.Argument(2), argumentList)
				v.Unlock()
				if err != nil {
					errMsg := err.Error()
					SendLogError(scriptIndex, errMsg)
					JobFailedHook(tag, cron, limit, errMsg)
				} else {
					JobPassedHook(tag, cron, limit)
				}
			}

			limitMsg := "infinite"
			if limit > 0 {
				limitMsg = fmt.Sprintf("%d", limit)
			}

			err = jobScheduler.RemoveByTag(tag)
			if err != nil {
				log.Debug().Err(err).Send()
			}

			s := jobScheduler.CronWithSeconds(cron).Tag(tag)
			if limit > 0 {
				s.LimitRunsTo(int(limit))
			}

			var job *gocron.Job
			job, err = s.Do(task)
			if err != nil {
				return throwError(call, err)
			}

			v.Jobs[tag] = job

			SendLog(scriptIndex, fmt.Sprintf("Scheduled the job: \"%s\" for cron: \"%s\" (limit: %s)", tag, cron, limitMsg))

			return otto.UndefinedValue()
		},
		"remove": func(call otto.FunctionCall) otto.Value {
			tag := FormatJobTag(call.Argument(0).String())

			err := jobScheduler.RemoveByTag(tag)
			if err != nil {
				return throwError(call, err)
			}

			SendLog(scriptIndex, fmt.Sprintf("Removed the job: \"%s\"", tag))

			return otto.UndefinedValue()
		},
		"removeAll": func(call otto.FunctionCall) otto.Value {
			jobScheduler.Clear()

			SendLog(scriptIndex, "All jobs are removed.")

			return otto.UndefinedValue()
		},
		"list": func(call otto.FunctionCall) otto.Value {
			var jobNames []string
			jobs := jobScheduler.Jobs()
			for _, job := range jobs {
				tags := job.Tags()
				if len(tags) == 0 {
					continue
				}

				jobNames = append(jobNames, tags[0])
			}

			o := otto.New()
			value, err := o.ToValue(jobNames)
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
		"run": func(call otto.FunctionCall) otto.Value {
			tag := FormatJobTag(call.Argument(0).String())

			err := jobScheduler.RunByTag(tag)
			if err != nil {
				return throwError(call, err)
			}

			SendLog(scriptIndex, fmt.Sprintf("Triggered the job: \"%s\"", tag))

			return otto.UndefinedValue()
		},
		"runAll": func(call otto.FunctionCall) otto.Value {
			jobScheduler.RunAll()

			SendLog(scriptIndex, "All jobs are triggered.")

			return otto.UndefinedValue()
		},
		"scheduler": map[string]interface{}{
			"isRunning": func(call otto.FunctionCall) otto.Value {
				value, err := otto.ToValue(jobScheduler.IsRunning())
				if err != nil {
					return throwError(call, err)
				}

				return value
			},
			"start": func(call otto.FunctionCall) otto.Value {
				jobScheduler.StartAsync()

				return otto.UndefinedValue()
			},
			"stop": func(call otto.FunctionCall) otto.Value {
				jobScheduler.Stop()

				return otto.UndefinedValue()
			},
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineKFL(o *otto.Otto, scriptIndex int64) {
	err := o.Set("kfl", map[string]interface{}{
		"match": func(call otto.FunctionCall) otto.Value {
			query := call.Argument(0).String()
			obj := call.Argument(1).Object()

			marshalled, err := obj.MarshalJSON()
			if err != nil {
				return throwError(call, err)
			}

			truth, _, err := kfl.Apply(marshalled, query)
			if err != nil {
				return throwError(call, err)
			}

			value, err := otto.ToValue(truth)
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
		"validate": func(call otto.FunctionCall) otto.Value {
			query := call.Argument(0).String()
			quiet, err := call.Argument(1).ToBoolean()
			if err != nil {
				return throwError(call, err)
			}

			isValid := true
			err = kfl.Validate(query)
			if err != nil {
				isValid = false
				if !quiet {
					SendLogError(scriptIndex, err.Error())
				}
			}

			value, err := otto.ToValue(isValid)
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineChatGPT(o *otto.Otto, scriptIndex int64) {
	err := o.Set("chatgpt", map[string]interface{}{
		"prompt": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("slack", scriptIndex) {
				return returnValue
			}

			apiKey := call.Argument(0).String()
			prompt := call.Argument(1).String()

			var maxTokens int64 = 1024
			if len(call.ArgumentList) > 2 {
				var err error
				maxTokens, err = call.Argument(2).ToInteger()
				if err != nil {
					return throwError(call, err)
				}
			}

			openaiEngine := openai.New(apiKey)
			ctx := context.Background()
			completionResp, err := openaiEngine.Completion(ctx, &openai.CompletionOptions{
				Model:     openai.ModelGPT3TextDavinci003,
				MaxTokens: int(maxTokens),
				Prompt:    []string{prompt},
			})
			if err != nil {
				return throwError(call, err)
			}

			value, err := otto.ToValue(strings.TrimSpace(completionResp.Choices[0].Text))
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
		"sentiment": func(call otto.FunctionCall) otto.Value {
			returnValue := otto.UndefinedValue()

			if protectLicense("slack", scriptIndex) {
				return returnValue
			}

			text := call.Argument(0).String()

			vader := sentitext.PolarityScore(sentitext.Parse(text, lexicon.DefaultLexicon))

			o := otto.New()
			value, err := o.ToValue(vader)
			if err != nil {
				return throwError(call, err)
			}

			return value
		},
	})

	if err != nil {
		log.Error().Err(err).Send()
	}
}

func defineHelpers(otto *otto.Otto, scriptIndex int64, node string, ip string, v *VM) {
	defineConsole(otto, scriptIndex)
	defineTest(otto, scriptIndex)
	defineVendor(otto, scriptIndex, node, ip)
	definePcap(otto, scriptIndex)
	defineFile(otto, scriptIndex)
	defineJobs(otto, scriptIndex, v)
	defineKFL(otto, scriptIndex)
	defineChatGPT(otto, scriptIndex)
}
