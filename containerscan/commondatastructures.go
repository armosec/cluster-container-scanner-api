package containerscan

import (
	"time"

	"github.com/armosec/armoapi-go/armotypes"
)

type CommonContainerVulnerabilityResult struct {
	Designators armotypes.PortalDesignator `json:"designators"`
	Context     []armotypes.ArmoContext    `json:"context"`

	WLID              string                                   `json:"wlid"`
	ContainerScanID   string                                   `json:"containersScanID"`
	Layers            []ESLayer                                `json:"layers"`
	Timestamp         int64                                    `json:"timestamp"`
	IsLastScan        int                                      `json:"isLastScan"`
	IsFixed           int                                      `json:"isFixed"`
	IntroducedInLayer string                                   `json:"layerHash"`
	RelevantLinks     []string                                 `json:"links"`                       // shitty SE practice
	RelatedExceptions []armotypes.VulnerabilityExceptionPolicy `json:"relatedExceptions,omitempty"` // configured in portal

	Vulnerability `json:",inline"`
}

type ESLayer struct {
	LayerHash       string `json:"layerHash"`
	ParentLayerHash string `json:"parentLayerHash"`
	LayerInfo       *LayerInfo
}

type LayerInfo struct {
	CreatedBy   string `json:"createdBy"`
	CreatedTime *time.Time
}

type SeverityStats struct {
	Severity                     string `json:"severity,omitempty"`
	TotalCount                   int64  `json:"total"`
	RCEFixCount                  int64  `json:"rceFixCount"`
	FixAvailableOfTotalCount     int64  `json:"fixedTotal"`
	RelevantCount                int64  `json:"totalRelevant"`
	FixAvailableForRelevantCount int64  `json:"fixedRelevant"`
	RCECount                     int64  `json:"rceTotal"`
	UrgentCount                  int64  `json:"urgent"`
	NeglectedCount               int64  `json:"neglected"`
	HealthStatus                 string `json:"healthStatus"`
}

type ShortVulnerabilityResult struct {
	Name string `json:"name"`
}

type CommonContainerScanSeveritySummary struct {
	Designators armotypes.PortalDesignator `json:"designators"`
	Context     []armotypes.ArmoContext    `json:"context"`
	JobIDs      []string                   `json:"jobIDs"`

	SeverityStats
	CustomerGUID    string `json:"customerGUID"`
	ContainerScanID string `json:"containersScanID"`
	Timestamp       int64  `json:"timestamp"`
	WLID            string `json:"wlid"`
	ImgTag          string `json:"imageTag"`
	ImgHash         string `json:"imageHash"`
	Cluster         string `json:"cluster"`
	Namespace       string `json:"namespace"`
	ContainerName   string `json:"containerName"`
	Status          string `json:"status"`
	Registry        string `json:"registry"`
	VersionImage    string `json:"versionImage"`
	Version         string `json:"version"`
	DayDate         string `json:"dayDate"`
}

type CommonContainerScanSummaryResult struct {
	SeverityStats
	Designators     armotypes.PortalDesignator `json:"designators"`
	Context         []armotypes.ArmoContext    `json:"context"`
	JobIDs          []string                   `json:"jobIDs"`
	CustomerGUID    string                     `json:"customerGUID"`
	ContainerScanID string                     `json:"containersScanID"`

	Timestamp     int64    `json:"timestamp"`
	WLID          string   `json:"wlid"`
	ImgTag        string   `json:"imageTag"`
	ImgHash       string   `json:"imageHash"`
	Cluster       string   `json:"cluster"`
	Namespace     string   `json:"namespace"`
	ContainerName string   `json:"containerName"`
	PackagesName  []string `json:"packages"`

	ListOfDangerousArtifcats []string `json:"listOfDangerousArtifcats"`

	Status string `json:"status"`

	Registry     string `json:"registry"`
	VersionImage string `json:"versionImage"`

	SeveritiesStats         []SeverityStats `json:"severitiesStats"`
	ExcludedSeveritiesStats []SeverityStats `json:"excludedSeveritiesStats,omitempty"`

	Version string `json:"version"`

	Vulnerabilities []ShortVulnerabilityResult `json:"vulnerabilities"`
}

func (summary *CommonContainerScanSummaryResult) Validate() bool {
	return summary.CustomerGUID != "" && summary.ContainerScanID != "" && (summary.ImgTag != "" || summary.ImgHash != "") && summary.Timestamp > 0
}
