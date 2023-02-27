package v1

import (
	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/cluster-container-scanner-api/containerscan"
	"github.com/francoispqt/gojay"
	"github.com/google/uuid"
)

func NewScanResultReport() containerscan.ScanReport {
	return &ScanResultReport{}
}

func (r *ScanResultReport) IsLastReport() bool {
	return r.PaginationInfo.IsLastReport
}

func (r *ScanResultReport) GetDesignators() armotypes.PortalDesignator {
	return r.Designators
}

func (r *ScanResultReport) GetContainerScanID() string {
	return r.ContainerScanID
}

func (r *ScanResultReport) GetTimestamp() int64 {
	return r.Timestamp
}

func (r *ScanResultReport) GetWorkloadHash() string {
	return r.GetDesignators().Attributes["workloadHash"]
}

func (r *ScanResultReport) GetCustomerGUID() string {
	return r.GetSummary().GetCustomerGUID()
}

func (r *ScanResultReport) GetSummary() containerscan.ContainerScanSummaryResult {
	if r.Summary == nil {
		return nil
	}
	return r.Summary
}

func (r *ScanResultReport) GetHasRelevancyData() bool {
	return r.HasRelevancyData
}

func (r *ScanResultReport) GetVulnerabilities() []containerscan.ContainerScanVulnerabilityResult {
	var vulnerabilities []containerscan.ContainerScanVulnerabilityResult
	for _, vul := range r.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, &vul)
	}
	return vulnerabilities
}

func NewContainerScanVulnerabilityResult() containerscan.ContainerScanVulnerabilityResult {
	return &containerscan.CommonContainerVulnerabilityResult{}
}

func (r *ScanResultReport) GetVersion() string {
	return "v1"
}

func (r *ScanResultReport) GetPaginationInfo() apis.PaginationMarks {
	return r.PaginationInfo
}

func (r *ScanResultReport) SetDesignators(designators armotypes.PortalDesignator) {
	r.Designators = designators
}

func (r *ScanResultReport) SetContainerScanID(containerScanID string) {
	r.ContainerScanID = containerScanID
}

func (r *ScanResultReport) SetTimestamp(timestamp int64) {
	r.Timestamp = timestamp
}

func (r *ScanResultReport) SetWorkloadHash(workloadHash string) {
	r.GetDesignators().Attributes["workloadHash"] = workloadHash
}

func (r *ScanResultReport) SetCustomerGUID(customerGUID string) {
	r.GetSummary().SetCustomerGUID(customerGUID)
}

func (r *ScanResultReport) SetPaginationInfo(paginationInfo apis.PaginationMarks) {
	r.PaginationInfo = paginationInfo
}

func (scanresult *ScanResultReport) Validate() bool {
	customerGuid := scanresult.Designators.Attributes[armotypes.AttributeCustomerGUID]
	if customerGuid == "" || scanresult.ContainerScanID == "" || scanresult.Timestamp <= 0 {
		return false
	}

	if _, err := uuid.Parse(customerGuid); err != nil {
		return false
	}
	return true
}

func (scan *ScanResultReport) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {
	switch key {
	case "timestamp":
		err = dec.Int64(&(scan.Timestamp))
	case "containersScanID":
		err = dec.String(&(scan.ContainerScanID))
	case "designators":
		err = dec.Object(&(scan.Designators))
	case "hasRelevancyData":
		err = dec.Bool(&(scan.HasRelevancyData))
	}
	return err
}

func (scan *ScanResultReport) NKeys() int {
	return 3
}
