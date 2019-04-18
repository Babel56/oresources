package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

func LogInit(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

type NodeInfo struct {
	Node struct {
		NodeName         string `json:"nodeName"`
		SystemContainers []struct {
			Name      string    `json:"name"`
			StartTime time.Time `json:"startTime"`
			CPU       struct {
				Time                 time.Time `json:"time"`
				UsageNanoCores       int       `json:"usageNanoCores"`
				UsageCoreNanoSeconds int64     `json:"usageCoreNanoSeconds"`
			} `json:"cpu"`
			Memory struct {
				Time            time.Time `json:"time"`
				UsageBytes      int       `json:"usageBytes"`
				WorkingSetBytes int       `json:"workingSetBytes"`
				RssBytes        int       `json:"rssBytes"`
				PageFaults      int64     `json:"pageFaults"`
				MajorPageFaults int       `json:"majorPageFaults"`
			} `json:"memory"`
			UserDefinedMetrics interface{} `json:"userDefinedMetrics"`
		} `json:"systemContainers"`
		StartTime time.Time `json:"startTime"`
		CPU       struct {
			Time                 time.Time `json:"time"`
			UsageNanoCores       int       `json:"usageNanoCores"`
			UsageCoreNanoSeconds int64     `json:"usageCoreNanoSeconds"`
		} `json:"cpu"`
		Memory struct {
			Time            time.Time `json:"time"`
			AvailableBytes  int64     `json:"availableBytes"`
			UsageBytes      int64     `json:"usageBytes"`
			WorkingSetBytes int64     `json:"workingSetBytes"`
			RssBytes        int64     `json:"rssBytes"`
			PageFaults      int       `json:"pageFaults"`
			MajorPageFaults int       `json:"majorPageFaults"`
		} `json:"memory"`
		Network struct {
			Time       time.Time `json:"time"`
			Name       string    `json:"name"`
			RxBytes    int64     `json:"rxBytes"`
			RxErrors   int       `json:"rxErrors"`
			TxBytes    int64     `json:"txBytes"`
			TxErrors   int       `json:"txErrors"`
			Interfaces []struct {
				Name     string `json:"name"`
				RxBytes  int64  `json:"rxBytes"`
				RxErrors int    `json:"rxErrors"`
				TxBytes  int64  `json:"txBytes"`
				TxErrors int    `json:"txErrors"`
			} `json:"interfaces"`
		} `json:"network"`
		Fs struct {
			Time           time.Time `json:"time"`
			AvailableBytes int64     `json:"availableBytes"`
			CapacityBytes  int64     `json:"capacityBytes"`
			UsedBytes      int64     `json:"usedBytes"`
			InodesFree     int       `json:"inodesFree"`
			Inodes         int       `json:"inodes"`
			InodesUsed     int       `json:"inodesUsed"`
		} `json:"fs"`
		Runtime struct {
			ImageFs struct {
				Time           time.Time `json:"time"`
				AvailableBytes int64     `json:"availableBytes"`
				CapacityBytes  int64     `json:"capacityBytes"`
				UsedBytes      int64     `json:"usedBytes"`
			} `json:"imageFs"`
		} `json:"runtime"`
	} `json:"node"`
	Pods []struct {
		PodRef struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"podRef"`
		StartTime  time.Time `json:"startTime"`
		Containers []struct {
			Name      string    `json:"name"`
			StartTime time.Time `json:"startTime"`
			CPU       struct {
				Time                 time.Time `json:"time"`
				UsageNanoCores       int       `json:"usageNanoCores"`
				UsageCoreNanoSeconds int64     `json:"usageCoreNanoSeconds"`
			} `json:"cpu"`
			Memory struct {
				Time            time.Time `json:"time"`
				UsageBytes      int       `json:"usageBytes"`
				WorkingSetBytes int       `json:"workingSetBytes"`
				RssBytes        int       `json:"rssBytes"`
				PageFaults      int       `json:"pageFaults"`
				MajorPageFaults int       `json:"majorPageFaults"`
			} `json:"memory"`
			Rootfs struct {
				Time           time.Time `json:"time"`
				AvailableBytes int64     `json:"availableBytes"`
				CapacityBytes  int64     `json:"capacityBytes"`
				UsedBytes      int       `json:"usedBytes"`
				InodesUsed     int       `json:"inodesUsed"`
			} `json:"rootfs"`
			Logs struct {
				Time           time.Time `json:"time"`
				AvailableBytes int64     `json:"availableBytes"`
				CapacityBytes  int64     `json:"capacityBytes"`
				UsedBytes      int       `json:"usedBytes"`
				InodesFree     int       `json:"inodesFree"`
				Inodes         int       `json:"inodes"`
				InodesUsed     int       `json:"inodesUsed"`
			} `json:"logs"`
			UserDefinedMetrics interface{} `json:"userDefinedMetrics"`
		} `json:"containers"`
		CPU struct {
			Time                 time.Time `json:"time"`
			UsageNanoCores       int       `json:"usageNanoCores"`
			UsageCoreNanoSeconds int64     `json:"usageCoreNanoSeconds"`
		} `json:"cpu"`
		Memory struct {
			Time            time.Time `json:"time"`
			UsageBytes      int       `json:"usageBytes"`
			WorkingSetBytes int       `json:"workingSetBytes"`
			RssBytes        int       `json:"rssBytes"`
			PageFaults      int       `json:"pageFaults"`
			MajorPageFaults int       `json:"majorPageFaults"`
		} `json:"memory,omitempty"`
		Network struct {
			Time       time.Time `json:"time"`
			Name       string    `json:"name"`
			RxBytes    int64     `json:"rxBytes"`
			RxErrors   int       `json:"rxErrors"`
			TxBytes    int64     `json:"txBytes"`
			TxErrors   int       `json:"txErrors"`
			Interfaces []struct {
				Name     string `json:"name"`
				RxBytes  int64  `json:"rxBytes"`
				RxErrors int    `json:"rxErrors"`
				TxBytes  int64  `json:"txBytes"`
				TxErrors int    `json:"txErrors"`
			} `json:"interfaces"`
		} `json:"network"`
		Volume []struct {
			Time           time.Time `json:"time"`
			AvailableBytes int64     `json:"availableBytes"`
			CapacityBytes  int64     `json:"capacityBytes"`
			UsedBytes      int64     `json:"usedBytes"`
			InodesFree     int       `json:"inodesFree"`
			Inodes         int       `json:"inodes"`
			InodesUsed     int       `json:"inodesUsed"`
			Name           string    `json:"name"`
			PvcRef         struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"pvcRef"`
		} `json:"volume"`
		EphemeralStorage struct {
			Time           time.Time `json:"time"`
			AvailableBytes int64     `json:"availableBytes"`
			CapacityBytes  int64     `json:"capacityBytes"`
			UsedBytes      int       `json:"usedBytes"`
			InodesFree     int       `json:"inodesFree"`
			Inodes         int       `json:"inodes"`
			InodesUsed     int       `json:"inodesUsed"`
		} `json:"ephemeral-storage"`
	} `json:"pods"`
}

type NodesSummary struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Metadata   struct {
		SelfLink        string `json:"selfLink"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Name              string    `json:"name"`
			SelfLink          string    `json:"selfLink"`
			UID               string    `json:"uid"`
			ResourceVersion   string    `json:"resourceVersion"`
			CreationTimestamp time.Time `json:"creationTimestamp"`
			Annotations       struct {
				VolumesKubernetesIoControllerManagedAttachDetach string `json:"volumes.kubernetes.io/controller-managed-attach-detach"`
			} `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			ExternalID string `json:"externalID"`
		} `json:"spec"`
		Status struct {
			Capacity struct {
				CPU    string `json:"cpu"`
				Memory string `json:"memory"`
				Pods   string `json:"pods"`
			} `json:"capacity"`
			Allocatable struct {
				CPU    string `json:"cpu"`
				Memory string `json:"memory"`
				Pods   string `json:"pods"`
			} `json:"allocatable"`
			Conditions []struct {
				Type               string    `json:"type"`
				Status             string    `json:"status"`
				LastHeartbeatTime  time.Time `json:"lastHeartbeatTime"`
				LastTransitionTime time.Time `json:"lastTransitionTime"`
				Reason             string    `json:"reason"`
				Message            string    `json:"message"`
			} `json:"conditions"`
			Addresses []struct {
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"addresses"`
			DaemonEndpoints struct {
				KubeletEndpoint struct {
					Port int `json:"Port"`
				} `json:"kubeletEndpoint"`
			} `json:"daemonEndpoints"`
			NodeInfo struct {
				MachineID               string `json:"machineID"`
				SystemUUID              string `json:"systemUUID"`
				BootID                  string `json:"bootID"`
				KernelVersion           string `json:"kernelVersion"`
				OsImage                 string `json:"osImage"`
				ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
				KubeletVersion          string `json:"kubeletVersion"`
				KubeProxyVersion        string `json:"kubeProxyVersion"`
				OperatingSystem         string `json:"operatingSystem"`
				Architecture            string `json:"architecture"`
			} `json:"nodeInfo"`
			Images []struct {
				Names     []string `json:"names"`
				SizeBytes int      `json:"sizeBytes"`
			} `json:"images"`
		} `json:"status"`
	} `json:"items"`
}

type WorkerPod struct {
	Token            string
	IsAlive          bool
	NodeInfoChan     chan *NodeInfo
	NodesList        map[string]bool
	ClusterResources *Resources
	WorkerLinks      map[string]*WorkerThread
	WorkerLinksChan  chan map[string]*WorkerThread
	WorkerStateChan  chan map[string]bool
}

type WorkerThread struct {
	Token           string
	Client          *http.Client
	Node            string
	NodeInfoChan    chan *NodeInfo
	Available       bool
	WorkerState     chan bool
	WorkerLinksChan chan map[string]*WorkerThread
	WorkerStateChan chan map[string]bool
}

type Resources struct {
	NodeResources map[string]*NodeResources
}

type NodeResources struct {
	NodeName   string
	Namespaces map[string]*Namespace
}

type Namespace struct {
	CpuMap        map[string]string
	MemoryMap     map[string]string
	PVStoragesMap map[string][]*Storage
}

type Storage struct {
	CapacityBytes int64
	UsedBytes     int64
	PvcName       string
}

func (workerPod *WorkerPod) Start() {
	workerPod.IsAlive = true
	go workerPod.NodesInfoWriter()
	go workerPod.NodesWorker()
	go workerPod.ThreadsStateController()
	workerPod.WebServer()
}

func (workerPod *WorkerPod) NodesInfoWriter() {
	Info.Println("NodesInfoWriter started.")
	for workerPod.IsAlive {
		select {
		case nodeInfo := <-workerPod.NodeInfoChan:
			var nodeResources NodeResources
			nodeResources.NodeName = nodeInfo.Node.NodeName
			nodeResources.Namespaces = make(map[string]*Namespace)
			for _, pod := range nodeInfo.Pods {
				if namespace, ok := nodeResources.Namespaces[pod.PodRef.Namespace]; ok {
					namespace.CpuMap[pod.PodRef.Name] = strconv.Itoa(pod.CPU.UsageNanoCores)
					namespace.MemoryMap[pod.PodRef.Name] = strconv.Itoa(pod.Memory.UsageBytes)
					for _, volume := range pod.Volume {
						if volume.PvcRef.Name != "" {
							namespace.PVStoragesMap[pod.PodRef.Name] = append(
								namespace.PVStoragesMap[pod.PodRef.Name],
								&Storage{
									CapacityBytes: volume.CapacityBytes,
									UsedBytes:     volume.UsedBytes,
									PvcName:       volume.PvcRef.Name})
						}
					}
				} else {
					var nNamespace Namespace
					nNamespace.CpuMap = make(map[string]string)
					nNamespace.MemoryMap = make(map[string]string)
					nNamespace.PVStoragesMap = make(map[string][]*Storage)
					nNamespace.CpuMap[pod.PodRef.Name] = strconv.Itoa(pod.CPU.UsageNanoCores)
					nNamespace.MemoryMap[pod.PodRef.Name] = strconv.Itoa(pod.Memory.UsageBytes)
					for _, volume := range pod.Volume {
						if volume.PvcRef.Name != "" {
							nNamespace.PVStoragesMap[pod.PodRef.Name] = append(
								nNamespace.PVStoragesMap[pod.PodRef.Name],
								&Storage{
									CapacityBytes: volume.CapacityBytes,
									UsedBytes:     volume.UsedBytes,
									PvcName:       volume.PvcRef.Name})
						}
					}

					nodeResources.Namespaces[pod.PodRef.Namespace] = &nNamespace
				}
			}
			workerPod.ClusterResources.NodeResources[nodeResources.NodeName] = &nodeResources
		}
	}
}

func (workerPod *WorkerPod) NodesWorker() {
	Info.Println("NodesWorker started.")
	for workerPod.IsAlive {
		workerPod.NodesList = workerPod.GetNodes()
		workerPod.ThreadsScheduler()
		time.Sleep(15 * time.Second)
	}
}

func (workerPod *WorkerPod) ThreadsStateController() {
	Info.Println("ThreadsStateController started.")
	for workerPod.IsAlive {
		select {
		case message := <-workerPod.WorkerLinksChan:
			for node, link := range message {
				workerPod.WorkerLinks[node] = link
			}
		case message := <-workerPod.WorkerStateChan:
			for node, state := range message {
				if !state {
					delete(workerPod.WorkerLinks, node)
				}
			}
		}
	}
}

func (workerPod *WorkerPod) ThreadsScheduler() {
	workerPod.CheckDeletedNodesThreads(workerPod.NodesList)
	for node, _ := range workerPod.NodesList {
		if _, ok := workerPod.WorkerLinks[node]; !ok {
			if workerPod.NodesList[node] {
				go workerPod.StartWorkerThread(node)
			}
		}
	}
}

func (workerPod *WorkerPod) CheckDeletedNodesThreads(nodesMap map[string]bool) {
	for nodeWorker, worker := range workerPod.WorkerLinks {
		if _, ok := nodesMap[nodeWorker]; !ok {
			go worker.Stop()
		} else {
			if !workerPod.NodesList[nodeWorker] {
				go worker.Stop()
			}
		}
	}
}

func (workerPod *WorkerPod) StartWorkerThread(nodeName string) {
	tr := &http.Transport{
		IdleConnTimeout:     1000 * time.Millisecond * time.Duration(15),
		TLSHandshakeTimeout: 1000 * time.Millisecond * time.Duration(15),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}
	worker := WorkerThread{
		Token:           workerPod.Token,
		Client:          &http.Client{Transport: tr},
		Node:            nodeName,
		NodeInfoChan:    workerPod.NodeInfoChan,
		Available:       true,
		WorkerState:     make(chan bool),
		WorkerStateChan: workerPod.WorkerStateChan,
		WorkerLinksChan: workerPod.WorkerLinksChan,
	}
	worker.Start()
}

func (worker *WorkerThread) Stop() {
	Info.Println(worker.Node, "node disconnected.")
	worker.Available = false
	worker.WorkerStateChan <- map[string]bool{
		worker.Node: false,
	}
}

func (worker *WorkerThread) Start() {
	worker.WorkerLinksChan <- map[string]*WorkerThread{
		worker.Node: worker,
	}
	worker.WorkerStateChan <- map[string]bool{
		worker.Node: true,
	}
	Info.Println(worker.Node, "node connected.")
	for worker.Available {
		bytesRepresentation, err := json.Marshal(map[string]interface{}{
			"pretty": "true",
		})
		if err != nil {
			Error.Println(err)
			return
		}
		req, err := http.NewRequest(
			"GET",
			ClusterAddr+"/api/v1/nodes/"+worker.Node+"/proxy/stats/summary",
			bytes.NewBuffer(bytesRepresentation))
		if err != nil {
			Error.Println(err)
			worker.Stop()
			return
		}
		req.Header.Add("Authorization", "Bearer "+worker.Token)
		req.Header.Add("Accept", "application/json")
		resp, err := worker.Client.Do(req)
		if err != nil {
			Error.Println("Error on response.\n[ERROR] -", err)
			worker.Stop()
			return
		}
		if resp != nil {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				Error.Println(err)
			}
			var nodeInfo NodeInfo
			if err := json.Unmarshal(body, &nodeInfo); err != nil {
				Warning.Println(err)
				worker.Stop()
			}
			worker.NodeInfoChan <- &nodeInfo
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
		time.Sleep(15 * time.Second)
	}
}

func (workerPod *WorkerPod) GetNodes() map[string]bool {
	nodesList := make(map[string]bool)
	bytesRepresentation, err := json.Marshal(map[string]interface{}{
		"pretty": "true",
	})
	if err != nil {
		Error.Println(err)
		return nil
	}
	req, err := http.NewRequest(
		"GET",
		ClusterAddr+"/api/v1/nodes",
		bytes.NewBuffer(bytesRepresentation))
	if err != nil {
		Error.Println(err)
		return nil
	}
	req.Header.Add("Authorization", "Bearer "+workerPod.Token)
	req.Header.Add("Accept", "application/json")
	tr := &http.Transport{
		IdleConnTimeout:     1000 * time.Millisecond * time.Duration(15),
		TLSHandshakeTimeout: 1000 * time.Millisecond * time.Duration(15),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		Error.Println("Error on response.\n[ERROR] -", err)
		return nil
	}
	if resp != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		var nodes NodesSummary
		if err := json.Unmarshal(body, &nodes); err != nil {
			Error.Println(err)
			return nil
		}
		for _, node := range nodes.Items {
			for _, state := range node.Status.Conditions {
				if state.Type == "Ready" {
					if state.Status == "True" {
						nodesList[node.Metadata.Name] = true
					} else {
						nodesList[node.Metadata.Name] = false
					}
				}
			}
		}
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}
	return nodesList
}

func (workerPod *WorkerPod) gracefulShutdownReciever(osChannel chan os.Signal) {
	sig := <-osChannel
	Info.Printf("caught sig: %+v", sig)
	Info.Println("Wait for 2 second to finish processing")
	time.Sleep(2 * time.Second)
	os.Exit(0)
}

func (workerPod *WorkerPod) ShowCPU(w http.ResponseWriter, r *http.Request) {
	var allCount = 0
	var podsMetricsMap = make(map[string]string)
	var namespacesMap = make(map[string]int)
	for _, node := range workerPod.ClusterResources.NodeResources {
		for namespaceName, namespace := range node.Namespaces {
			var cpuCount = 0
			for key, value := range namespace.CpuMap {
				podsMetricsMap["pod_cpu_usage_nanocores{namespace=\""+namespaceName+"\", podname=\""+key+"\"}"] = value
				cpuInt, err := strconv.Atoi(value)
				if err != nil {
					Error.Println(err)
				} else {
					cpuCount = cpuCount + cpuInt
					allCount = allCount + cpuInt
				}
			}
			if _, ok := namespacesMap[namespaceName]; !ok {
				namespacesMap[namespaceName] = cpuCount
			} else {
				namespacesMap[namespaceName] = namespacesMap[namespaceName] + cpuCount
			}
		}
	}
	for metric, value := range podsMetricsMap {
		fmt.Fprintln(w, metric, value)
	}
	for namespace, value := range namespacesMap {
		fmt.Fprintln(w, "namespace_cpu_usage_nanocores{namespace=\""+namespace+"\"}", value)
	}
	clusterMetricString := "cluster_cpu_usage_nanocores"
	fmt.Fprintln(w, clusterMetricString, allCount)
}

func (workerPod *WorkerPod) ShowMem(w http.ResponseWriter, r *http.Request) {
	var allCount = 0
	var podsMetricsMap = make(map[string]string)
	var namespacesMap = make(map[string]int)
	for _, node := range workerPod.ClusterResources.NodeResources {
		for namespaceName, namespace := range node.Namespaces {
			var memCount = 0
			for key, value := range namespace.MemoryMap {
				podsMetricsMap["pod_memory_usage_bytes{namespace=\""+namespaceName+"\", podname=\""+key+"\"}"] = value
				memInt, err := strconv.Atoi(value)
				if err != nil {
					Error.Println(err)
				} else {
					memCount = memCount + memInt
					allCount = allCount + memInt
				}
			}
			if _, ok := namespacesMap[namespaceName]; !ok {
				namespacesMap[namespaceName] = memCount
			} else {
				namespacesMap[namespaceName] = namespacesMap[namespaceName] + memCount
			}
		}
	}
	for metric, value := range podsMetricsMap {
		fmt.Fprintln(w, metric, value)
	}
	for namespace, value := range namespacesMap {
		fmt.Fprintln(w, "namespace_memory_usage_bytes{namespace=\""+namespace+"\"}", value)
	}
	fmt.Fprintln(w, "cluster_memory_usage_bytes", allCount)
}

func (workerPod *WorkerPod) ShowStorages(w http.ResponseWriter, r *http.Request) {
	var clusterCapacity int64
	var clusterUsed int64
	var namespaceCapacity = make(map[string]int64)
	var namespaceUsed = make(map[string]int64)
	var podsStorages = make(map[string]int64)
	for _, node := range workerPod.ClusterResources.NodeResources {
		for namespaceName, namespace := range node.Namespaces {
			for podname, storages := range namespace.PVStoragesMap {
				for _, storage := range storages {
					podsStorages["pod_storage_bytes{namespace=\""+namespaceName+"\", podname=\""+podname+"\", pvcname=\""+storage.PvcName+"\", type=\"capacity\"}"] = storage.CapacityBytes
					podsStorages["pod_storage_bytes{namespace=\""+namespaceName+"\", podname=\""+podname+"\", pvcname=\""+storage.PvcName+"\", type=\"used\"}"] = storage.UsedBytes
					namespaceCapacity[namespaceName] = namespaceCapacity[namespaceName] + storage.CapacityBytes
					namespaceUsed[namespaceName] = namespaceUsed[namespaceName] + storage.UsedBytes
					clusterCapacity = clusterCapacity + storage.CapacityBytes
					clusterUsed = clusterUsed + storage.UsedBytes
				}
			}
		}
	}
	for metric, value := range podsStorages {
		fmt.Fprintln(w, metric, value)
	}
	for namespace, value := range namespaceCapacity {
		fmt.Fprintln(w, "namespace_storage_bytes{namespace=\""+namespace+"\", type=\"capacity\"}", value)
	}
	for namespace, value := range namespaceUsed {
		fmt.Fprintln(w, "namespace_storage_bytes{namespace=\""+namespace+"\" type=\"used\"}", value)
	}
	fmt.Fprintln(w, "cluster_storage_capacity_bytes", clusterCapacity)
	fmt.Fprintln(w, "cluster_storage_used_bytes", clusterUsed)
}

func (workerPod *WorkerPod) WebServer() {
	router := mux.NewRouter()
	router.HandleFunc("/cpu", workerPod.ShowCPU)
	router.HandleFunc("/mem", workerPod.ShowMem)
	router.HandleFunc("/storage", workerPod.ShowStorages)
	httpServer := &http.Server{
		Handler:      router,
		Addr:         "0.0.0.0:8080",
		IdleTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  30 * time.Second,
	}
	var gracefulStop = make(chan os.Signal)
	signal.Notify(gracefulStop, syscall.SIGTERM)
	signal.Notify(gracefulStop, syscall.SIGINT)
	go workerPod.gracefulShutdownReciever(gracefulStop)
	if err := httpServer.ListenAndServe(); err != nil {
		Error.Println("Web Server Error:", err)
	}
}

var (
	ClusterAddr string
)

func SetClusterAddrFromEnv() {
	addr := os.Getenv("CLUSTER_ADDR")
	if addr == "" {
		ClusterAddr = "https://172.30.0.1:443"
	} else {
		ClusterAddr = addr
	}
}

func GetTokenFromEnv() (string, bool) {
	token := os.Getenv("AUTH_TOKEN")
	if token == "" {
		Error.Println("Unable to get auth token from ENV.")
		return "", false
	} else {
		return token, true
	}
}

func Configure() *WorkerPod {
	var workerPod WorkerPod
	token, success := GetTokenFromEnv()
	if !success {
		return nil
	}
	SetClusterAddrFromEnv()
	workerPod.Token = token
	workerPod.ClusterResources = &Resources{
		NodeResources: make(map[string]*NodeResources),
	}
	workerPod.NodeInfoChan = make(chan *NodeInfo)
	workerPod.WorkerLinksChan = make(chan map[string]*WorkerThread)
	workerPod.WorkerLinks = make(map[string]*WorkerThread)
	workerPod.WorkerStateChan = make(chan map[string]bool)
	return &workerPod
}

func StartService() {
	pod := Configure()
	if pod != nil {
		pod.Start()
	} else {
		os.Exit(2)
	}
}

func init() {
	LogInit(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
}

func main() {
	StartService()
}
