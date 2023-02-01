package vm

import (
	"sync"

	"github.com/robertkrimen/otto"
)

var vms *sync.Map

type VM struct {
	Otto *otto.Otto
	Code string
}

func Init() {
	vms = &sync.Map{}
}

func CreateVM(code string) (*VM, error) {
	o := otto.New()
	defineHelpers(o)
	_, err := o.Run(code)
	if err != nil {
		return nil, err
	}
	return &VM{
		Otto: o,
		Code: code,
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
