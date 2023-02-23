package containerscan

import (
	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
)

type ScanReport interface {
	IsLastReport() bool
	GetDesignators() armotypes.PortalDesignator
	GetContainerScanID() string
	GetTimestamp() int64
	GetWorkloadHash() string
	GetCustomerGUID() string
	GetSummary() ContainerScanSummaryResult
	GetVulnerabilities() []ContainerScanVulnerabilityResult
	GetVersion() string
	GetPaginationInfo() apis.PaginationMarks
	GetHasRelevancyData() bool
	Validate() bool

	SetDesignators(armotypes.PortalDesignator)
	SetContainerScanID(string)
	SetTimestamp(int64)
	SetWorkloadHash(string)
	SetCustomerGUID(string)
}

type ContainerScanSummaryResult interface {
	GetDesignators() armotypes.PortalDesignator
	GetContext() []armotypes.ArmoContext
	GetWLID() string
	GetImageTag() string
	GetImageID() string
	GetSeverityStats() SeverityStats
	GetSeveritiesStats() []SeverityStats
	GetClusterName() string
	GetNamespace() string
	GetContainerName() string
	GetStatus() string
	GetRegistry() string
	GetImageTageSuffix() string
	GetVersion() string
	GetCustomerGUID() string
	GetContainerScanID() string
	GetTimestamp() int64
	GetJobIDs() []string
	Validate() bool

	SetDesignators(armotypes.PortalDesignator)
	SetContext([]armotypes.ArmoContext)
	SetWLID(string)
	SetImageTag(string)
	SetImageID(string)
	SetSeverityStats(SeverityStats)
	SetSeveritiesStats([]SeverityStats)
	SetClusterName(string)
	SetNamespace(string)
	SetContainerName(string)
	SetStatus(string)
	SetRegistry(string)
	SetImageTageSuffix(string)
	SetVersion(string)
	SetCustomerGUID(string)
	SetContainerScanID(string)
	SetTimestamp(int64)
}

type ContainerScanVulnerabilityResult interface {
	GetDesignators() armotypes.PortalDesignator
	GetContext() []armotypes.ArmoContext
	GetWLID() string
	GetContainerScanID() string
	GetLayers() []ESLayer
	GetLayersNested() []ESLayer
	GetTimestamp() int64
	GetIsLastScan() int
	GetIsFixed() int
	GetIntroducedInLayer() string
	GetRelevantLinks() []string
	GetRelatedExceptions() []armotypes.VulnerabilityExceptionPolicy
	GetVulnerability() VulnerabilityResult

	SetDesignators(designators armotypes.PortalDesignator)
	SetContext(context []armotypes.ArmoContext)
	SetWLID(wlid string)
	SetContainerScanID(containerScanID string)
	SetLayers(layers []ESLayer)
	SetLayersNested(layersNested []ESLayer)
	SetTimestamp(timestamp int64)
	SetIsLastScan(isLastScan int)
	SetIsFixed(isFixed int)
	SetIntroducedInLayer(introducedInLayer string)
	SetRelevantLinks(relevantLinks []string)
	SetRelatedExceptions(relatedExceptions []armotypes.VulnerabilityExceptionPolicy)
}

type VulnerabilityResult interface {
	GetName() string
	GetImageID() string
	GetImageTag() string
	GetRelatedPackageName() string
	GetPackageVersion() string
	GetLink() string
	GetDescription() string
	GetSeverity() string
	GetSeverityScore() int
	GetFixes() VulFixes
	GetIsRelevant() *bool
	GetUrgentCount() int
	GetNeglectedCount() int
	GetHealthStatus() string
	GetCategories() VulnerabilityCategory
	GetExceptionApplied() []armotypes.VulnerabilityExceptionPolicy

	SetName(string)
	SetImageID(string)
	SetImageTag(string)
	SetRelatedPackageName(string)
	SetPackageVersion(string)
	SetLink(string)
	SetDescription(string)
	SetSeverity(string)
	SetSeverityScore(int)
	SetFixes(VulFixes)
	SetIsRelevant(*bool)
	SetUrgentCount(int)
	SetNeglectedCount(int)
	SetHealthStatus(string)
	SetCategories(VulnerabilityCategory)
	SetExceptionApplied([]armotypes.VulnerabilityExceptionPolicy)
}
