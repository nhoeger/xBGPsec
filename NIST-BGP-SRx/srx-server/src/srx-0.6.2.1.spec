%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

%define package_num  0
%define major_ver    6
%define minor_ver    2
%define update_num   1
%define lib_ver_info 6.0.2

%define lib_version_info %{lib_ver_info}
%define package_version %{package_num}.%{major_ver}.%{minor_ver}.%{update_num}
%define version %{package_version}
%define name srx
%define _unpackaged_files_terminate_build 0

Name:%{name}
Version:%{version}
Release:1%{?dist}
Summary:This package provides the SRx server for RPKI origin validation and BGPsec path validation including tools
Group:Networking/Daemons
License:https://www.nist.gov/director/copyright-fair-use-and-licensing-statements-srd-data-and-software
URL:https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype
Vendor:National Institute of Standards and Technology (NIST)
Distribution:NIST BGP-SRx Software Suite
Packager:BGP-SRx Dev <itrg-contact@list.nist.gov>

Source0:%{name}-%{version}.tar.gz
BuildRoot:/tmp/rpm/%{name}-%{version}	
Prefix: %{_prefix}
Prefix: %{_sysconfdir}

BuildRequires:automake
Requires(pre): srxcryptoapi >= 0.3.0 srxcryptoapi < 0.4.0
Requires:glibc libconfig >= 1.3 openssl >= 1.0.1e readline >= 6.0 srxcryptoapi >= 0.3.0 srxcryptoapi < 0.4.0

%description
The SRx-Server allows to out-source the validation of BGP updates using RPKI 
processing (RFC6811) and BGPsec path validation (RFC8205). The SRx-server allows
to provide RPKI and BGPsec path processing to more than one router. 
The srx-server can be accessed remotely using a telnet client.

In addition to the srx-server this package provides an RPKI test harness that 
emulates an RPKI cache allowing to feed ROA's and PKI keys to the srx-server 
using the rtr-to-cache protocol (RFC8210).


%prep
%setup -q

%build
%configure --prefix=/usr --sysconfdir=/etc sca_dir=/home/nils/Dokumente/ASPA+/NIST-BGP-SRx/local-6.3.3 patricia_dir= 
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%post
chmod go+rx %{_initddir}/srx_serverd
chkconfig --add srx_serverd
chkconfig srx_serverd off

%preun
service srx_serverd stop
chkconfig --del srx_serverd
if [ -e %{_sysconfdir}/srx_server.conf ] ; then
 echo "  - save server configuration as %{_sysconfdir}/srx_server.conf.rpmsafe"
 cp -f %{_sysconfdir}/srx_server.conf %{_sysconfdir}/srx_server.conf.rpmsafe
fi

%postun

%files
#%defattr(644,root,root,755)
%defattr(-,root,root,-)
%doc
%{_sysconfdir}/srx_server.conf
%{_initddir}/srx_serverd
%{_bindir}/srx_server
%{_bindir}/rpkirtr_client
%{_bindir}/rpkirtr_svr
