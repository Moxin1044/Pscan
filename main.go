package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	// 解析参数
	filename := flag.String("F", "ip.txt", "文件名称")
	port := flag.Int("P", 0, "端口号")
	threads := flag.Int("T", 0, "线程数")
	outputfile := flag.String("O", "outfile.txt", "结果保存的文件")
	openOnly := flag.Bool("OF", true, "是否只输出开放的端口信息")
	timeout := flag.Duration("timeout", 2*time.Second, "连接超时时间")
	flag.Parse()

	if *filename == "" || *port == 0 || *threads == 0 {
		// Warning: 一定要注意修改了解析参数就一定要修改使用方法，后续也要在Readme进行补充。
		fmt.Println("使用方法: \n Windows: Pscan.exe -F <file name> -P <port number> -T <number of threads> \n Mac or Linux: Pscan -F <file name> -P <port number> -T <number of threads>\n 更多高级用法请参考GitHub：https://github.com/Moxin1044/Pscan")
		return
	}

	file, err := os.Open(*filename)
	if err != nil {
		fmt.Println("无法打开文件:", err)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var wg sync.WaitGroup
	sem := make(chan struct{}, *threads)
	var saveList []string // 创建保存结果的列表
	for scanner.Scan() {
		ip := scanner.Text()
		sem <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			saveList = append(saveList, checkPort(ip, *port, *timeout, *openOnly))
		}(ip)
	}
	wg.Wait()
	// 只有在扫描完成后才进行保存，这样虽然会导致内存占用和消耗，但是提升了性能，比如扫描过程中的性能，并且减少磁盘损伤。
	// 如果后续有时间，可以给扫描、保存分为两个主线程，在两个线程池中进行不同的操作。
	of, err := os.Create(*outputfile)
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return
	}
	defer of.Close()

	for _, item := range saveList {
		of.WriteString(item + "\n")
	}

}

func checkPort(ip string, port int, timeout time.Duration, openOnly bool) string {
	address := ip + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if openOnly == true {
		// 如果openOnly为真，则只返回端口为打开的IP和端口
		if err != nil {
			fmt.Printf("%s:%d closed\n", ip, port)
			return "" // 这里需要一个返回，否则会导致继续执行下面的内容，如果不这样写就需要else。
		}

		conn.Close()
		fmt.Printf("%s:%d open\n", ip, port)
		return ip + ":" + strconv.Itoa(port)
	} else {
		// 如果不为真，则返回未打开的IP和端口
		if err != nil {
			fmt.Printf("%s:%d closed\n", ip, port)
			return ip + ":" + strconv.Itoa(port)
		}

		conn.Close()
		fmt.Printf("%s:%d open\n", ip, port)
		return ""
	}
}
