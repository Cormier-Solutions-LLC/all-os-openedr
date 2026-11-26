Name:           all-os-openedr
Version:        %{openedr_version}
Release:        1.%{openedr_target}
Summary:        OpenEDR process telemetry preview for Linux
License:        LicenseRef-CASL
Source0:        all-os-openedr.tar.gz
BuildArch:      noarch
BuildRequires:  systemd-rpm-macros
Requires:       /usr/bin/%{openedr_python}

%{?systemd_requires}

%description
An unprivileged process telemetry collector that writes local JSON events.

%prep
%setup -q -n all-os-openedr

%install
install -d %{buildroot}%{_prefix}/lib/%{name}/all_os_openedr
install -m 0644 all_os_openedr/*.py %{buildroot}%{_prefix}/lib/%{name}/all_os_openedr/
install -D -m 0644 all-os-openedr.service %{buildroot}%{_unitdir}/all-os-openedr.service
install -D -m 0644 80-all-os-openedr.preset %{buildroot}%{_presetdir}/80-all-os-openedr.preset

%post
%systemd_post all-os-openedr.service

%preun
%systemd_preun all-os-openedr.service

%postun
%systemd_postun_with_restart all-os-openedr.service

%files
%license LICENSE.md NOTICE.md
%{_prefix}/lib/%{name}/
%{_unitdir}/all-os-openedr.service
%{_presetdir}/80-all-os-openedr.preset
