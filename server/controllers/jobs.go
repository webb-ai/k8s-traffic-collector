package controllers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron"
	"github.com/kubeshark/worker/vm"
)

type ResultJob struct {
	Tag              string    `json:"tag"`
	LastRun          time.Time `json:"lastRun"`
	NextRun          time.Time `json:"nextRun"`
	RunCount         int       `json:"runCount"`
	ScheduledAtTimes []string  `json:"scheduledAtTimes"`
	IsRunning        bool      `json:"isRunning"`
	IsPending        bool      `json:"isPending"`
}

func (j *ResultJob) Fill(x *gocron.Job) {
	tags := x.Tags()
	if len(tags) > 0 {
		j.Tag = tags[0]
	}

	j.LastRun = x.LastRun().UTC()
	j.NextRun = x.NextRun().UTC()
	j.RunCount = x.RunCount()
	j.ScheduledAtTimes = x.ScheduledAtTimes()
	j.IsRunning = x.IsRunning()

	if time.Now().UTC().After(j.NextRun) {
		j.IsPending = true
	}
}

func GetJob(c *gin.Context) {
	tag := c.Param("tag")

	jobs, err := vm.GetJobScheduler().FindJobsByTag(tag)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	job := jobs[0]
	resultJob := &ResultJob{}
	resultJob.Fill(job)
	c.JSON(http.StatusOK, resultJob)
}

func DeleteJob(c *gin.Context) {
	tag := c.Param("tag")

	err := vm.GetJobScheduler().RemoveByTag(tag)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
}

func PostRunJob(c *gin.Context) {
	tag := c.Param("tag")

	err := vm.GetJobScheduler().RunByTag(tag)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}
}

func PostRunAllJobs(c *gin.Context) {
	vm.GetJobScheduler().RunAll()
}

func GetAllJobs(c *gin.Context) {
	var resultJobs []*ResultJob
	jobs := vm.GetJobScheduler().Jobs()

	for _, job := range jobs {
		resultJob := &ResultJob{}
		resultJob.Fill(job)
		resultJobs = append(resultJobs, resultJob)
	}

	c.JSON(http.StatusOK, gin.H{
		"jobs": resultJobs,
	})
}

func DeleteAllJobs(c *gin.Context) {
	vm.GetJobScheduler().Clear()
}

func GetSchedulerStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"isRunning": vm.GetJobScheduler().IsRunning(),
	})
}

func PostSchedulerStart(c *gin.Context) {
	vm.GetJobScheduler().StartAsync()
}

func PostSchedulerStop(c *gin.Context) {
	vm.GetJobScheduler().Stop()
}
