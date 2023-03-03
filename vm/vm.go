package vm

import (
	"sync"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/robertkrimen/otto"
	"github.com/rs/zerolog/log"
)

var vms *sync.Map
var jobScheduler *gocron.Scheduler

type VM struct {
	Otto *otto.Otto
	Code string
	Jobs map[string]*gocron.Job
	sync.Mutex
}

func Init() {
	vms = &sync.Map{}

	jobScheduler = gocron.NewScheduler(time.UTC)
	jobScheduler.TagsUnique()
	jobScheduler.SingletonModeAll()

	jobScheduler.StartAsync()
}

func Create(key int64, code string, license bool, node string, ip string) (*VM, error) {
	o := otto.New()

	v := &VM{
		Otto: o,
		Code: code,
		Jobs: make(map[string]*gocron.Job),
	}

	defineEnv(o)
	defineHelpers(o, key, license, node, ip, v)

	v.Lock()
	_, err := o.Run(code)
	v.Unlock()
	if err != nil {
		return nil, err
	}

	return v, nil
}

func Set(key int64, v *VM) {
	oldV, ok := Get(key)
	if ok {
		for _, job := range oldV.Jobs {
			jobScheduler.RemoveByReference(job)
		}
	}

	vms.Store(key, v)
}

func Get(key int64) (*VM, bool) {
	v, ok := vms.Load(key)
	if !ok {
		return nil, ok
	}

	return v.(*VM), ok
}

func Delete(key int64) {
	v, ok := Get(key)
	if !ok {
		log.Error().Int64("index", key).Msg("Couldn't find the VM!")
	} else {
		for _, job := range v.Jobs {
			jobScheduler.RemoveByReference(job)
		}
	}

	vms.Delete(key)
}

func Range(f func(key, value interface{}) bool) {
	vms.Range(f)
}

func Len() uint {
	var i uint
	vms.Range(func(key, value interface{}) bool {
		i++
		return true
	})

	return i
}

func GetJobScheduler() *gocron.Scheduler {
	return jobScheduler
}
