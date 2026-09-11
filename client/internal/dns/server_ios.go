package dns

func (s *DefaultServer) initialize() (manager hostManager, err error) {
	return newMobileHostManager(s.mobileDNSManager)
}
