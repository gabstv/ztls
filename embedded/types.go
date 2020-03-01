package embedded

type CSRReader interface {
	GetCommonName() string
	GetCountry() []string
	GetProvince() []string
	GetLocality() []string
	GetOrganization() []string
	GetOrganizationalUnit() []string
	GetStreetAddress() []string
	GetPostalCode() []string
	GetIPs() []string
	GetDomains() []string
}

type CSRWriter interface {
	SetCommonName(string) CSRWriter
	SetCountry([]string) CSRWriter
	SetProvince([]string) CSRWriter
	SetLocality([]string) CSRWriter
	SetOrganization([]string) CSRWriter
	SetOrganizationalUnit([]string) CSRWriter
	SetStreetAddress([]string) CSRWriter
	SetPostalCode([]string) CSRWriter
	SetIPs([]string) CSRWriter
	SetDomains([]string) CSRWriter
}

type CSR interface {
	CSRReader
	CSRWriter
}

type CSRJson struct {
	CommonName         string   `json:"common_name"`         // [REQUIRED] Usually the publicly acessible domain name or IP address.
	Country            []string `json:"country"`             // [OPTIONAL] Alpha2 Country Code
	Province           []string `json:"province"`            // [OPTIONAL]
	Locality           []string `json:"locality"`            // [OPTIONAL]
	Organization       []string `json:"organization"`        // [OPTIONAL] Organization Name
	OrganizationalUnit []string `json:"organizational_unit"` // [OPTIONAL]
	StreetAddress      []string `json:"street_address"`      // [OPTIONAL]
	PostalCode         []string `json:"postal_code"`         // [OPTIONAL]
	IPs                []string `json:"ips"`                 // [OPTIONAL] Additional IPs
	Domains            []string `json:"domains"`             // [OPTIONAL] Additional Domains
}

func (j CSRJson) GetCommonName() string           { return j.CommonName }
func (j CSRJson) GetCountry() []string            { return j.Country }
func (j CSRJson) GetProvince() []string           { return j.Province }
func (j CSRJson) GetLocality() []string           { return j.Locality }
func (j CSRJson) GetOrganization() []string       { return j.Organization }
func (j CSRJson) GetOrganizationalUnit() []string { return j.OrganizationalUnit }
func (j CSRJson) GetStreetAddress() []string      { return j.StreetAddress }
func (j CSRJson) GetPostalCode() []string         { return j.PostalCode }
func (j CSRJson) GetIPs() []string                { return j.IPs }
func (j CSRJson) GetDomains() []string            { return j.Domains }

func (j *CSRJson) SetCommonName(v string) CSRWriter {
	j.CommonName = v
	return j
}
func (j *CSRJson) SetCountry(v []string) CSRWriter {
	j.Country = v
	return j
}
func (j *CSRJson) SetProvince(v []string) CSRWriter {
	j.Province = v
	return j
}
func (j *CSRJson) SetLocality(v []string) CSRWriter {
	j.Locality = v
	return j
}
func (j *CSRJson) SetOrganization(v []string) CSRWriter {
	j.Organization = v
	return j
}
func (j *CSRJson) SetOrganizationalUnit(v []string) CSRWriter {
	j.OrganizationalUnit = v
	return j
}
func (j *CSRJson) SetStreetAddress(v []string) CSRWriter {
	j.StreetAddress = v
	return j
}
func (j *CSRJson) SetPostalCode(v []string) CSRWriter {
	j.PostalCode = v
	return j
}
func (j *CSRJson) SetIPs(v []string) CSRWriter {
	j.IPs = v
	return j
}
func (j *CSRJson) SetDomains(v []string) CSRWriter {
	j.Domains = v
	return j
}
