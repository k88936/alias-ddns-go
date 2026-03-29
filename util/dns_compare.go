package util

// DNSCompareResult represents the result of comparing DNS records
type DNSCompareResult struct {
	CurrentRecords map[string]string // map[IP]RecordID
	DesiredIPs     map[string]bool   // Set of desired IPs
	ToDelete       []string          // Record IDs to delete
	ToCreate       []string          // IPs to create
}

// CompareDNSRecords compares current DNS records with desired IPs and returns what needs to be changed
// attection ALWAYS create new before del old
func CompareDNSRecords(currentRecords map[string]string, desiredIPs []string) *DNSCompareResult {
	result := &DNSCompareResult{
		CurrentRecords: currentRecords,
		DesiredIPs:     make(map[string]bool),
		ToCreate:       []string{},
		ToDelete:       []string{},
	}

	// Build desired IPs set
	for _, ip := range desiredIPs {
		result.DesiredIPs[ip] = true
	}

	// Calculate records to delete (current has but desired doesn't)
	for ip, recordID := range currentRecords {
		if !result.DesiredIPs[ip] {
			result.ToDelete = append(result.ToDelete, recordID)
		}
	}

	// Calculate records to create (desired has but current doesn't)
	for _, ip := range desiredIPs {
		if _, exists := currentRecords[ip]; !exists {
			result.ToCreate = append(result.ToCreate, ip)
		}
	}

	return result
}
