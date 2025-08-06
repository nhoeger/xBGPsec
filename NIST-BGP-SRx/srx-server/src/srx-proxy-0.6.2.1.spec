%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

%define package_num  0
%define major_ver    6
%define minor_ver    2
%define update_num   1
%define lib_ver_info 6.0.2
%define srxdir       srx

%define lib_version_info %{lib_ver_info}
%define package_version %{package_num}.%{major_ver}.%{minor_ver}.%{update_num}
%define version %{package_version}
%define name srx-proxy
%define core_name srx
%define _unpackaged_files_terminate_build 0

Name:%{name}
Version:%{version}
Release:1%{?dist}
Summary:Package provides the SRx Proxy
Group:Networking/Daemons
License:https://www.nist.gov/director/copyright-fair-use-and-licensing-statements-srd-data-and-software
URL:https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype
Vendor:National Institute of Standards and Technology (NIST)
Distribution:NIST BGP-SRx Software Suite
Packager:BGP-SRx Dev <itrg-contact@list.nist.gov>

Source0:%{core_name}-%{version}.tar.gz
BuildRoot:/tmp/rpm/%{core_name}-%{version}	
Prefix: %{_prefix}
Prefix: %{_sysconfdir}

BuildRequires:automake	
Requires:glibc

%description
The SRx-Proxy allows routers to connect to the srx-server using API calls.
Additionally this package provides an srxsrv_client

%prep
%setup -q -n %{core_name}-%{version}

%build
%configure --prefix=/usr --sysconfdir=/etc sca_dir=/home/nils/Dokumente/ASPA+/NIST-BGP-SRx/local-6.3.3 patricia_dir= 
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%post
ldconfig

%preun

%postun
if [ "$(ls -A %{_libdir}/srx)" == "" ] ; then
  rmdir %{_libdir}/%{srxdir}
fi 
if [ "$(ls -A %{_includedir}/%{srxdir})" == "" ] ; then
  rmdir %{_includedir}/%{srxdir}
fi 
ldconfig

%files
#%defattr(644,root,root,755)
%defattr(-,root,root,-)
%doc
%{_sysconfdir}/ld.so.conf.d/srxproxy64.conf
%{_libdir}/%{srxdir}/libSRxProxy.so
%{_libdir}/%{srxdir}/libSRxProxy.so.%{major_ver}
%{_libdir}/%{srxdir}/libSRxProxy.so.%{lib_version_info}
%if "no" == "yes" 
  %{_libdir}/%{srxdir}/libSRxProxy.la
  %{_libdir}/%{srxdir}/libSRxProxy.a
%else
  %exclude %{_libdir}/%{srxdir}/libSRxProxy.la
  %exclude %{_libdir}/%{srxdir}/libSRxProxy.a
%endif
%exclude %{_includedir}/%{srxdir}/srx_defs.h
%exclude %{_includedir}/%{srxdir}/srx_api.h
%exclude %{_includedir}/%{srxdir}/slist.h
%exclude %{_includedir}/%{srxdir}/prefix.h
%{_bindir}/srxsvr_client
%exclude %{_sysconfdir}/srx_server.conf
%exclude %{_initddir}/srx_serverd
%exclude %{_bindir}/srx_server
%exclude %{_bindir}/rpkirtr_client
%exclude %{_bindir}/rpkirtr_svr
