package vm

import (
	"sync"

	"github.com/robertkrimen/otto"
)

var vms *sync.Map

type VM struct {
	Otto       *otto.Otto
	Code       string
	LogChannel chan *Log
}

func Init() {
	vms = &sync.Map{}
}

func Create(key int64, code string, logChannel chan *Log, license bool) (*VM, error) {
	o := otto.New()
	defineHelpers(o, logChannel, key, license)
	_, err := o.Run(code)
	if err != nil {
		return nil, err
	}

	return &VM{
		Otto:       o,
		Code:       code,
		LogChannel: logChannel,
	}, nil
}

func Set(key int64, vm *VM) {
	vms.Store(key, vm)
}

func Get(key int64) (*VM, bool) {
	v, ok := vms.Load(key)
	return v.(*VM), ok
}

func Delete(key int64) {
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
