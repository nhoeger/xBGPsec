%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

%define package_num  0
%define major_ver    6
%define minor_ver    2
%define update_num   1
%define lib_ver_info 6.0.2
%define srxdir       srx

%define CLIENT_DIR src/client
%define SHARED_DIR src/shared
%define UTIL_DIR   src/util

%define lib_version_info %{lib_ver_info}
%define package_version %{package_num}.%{major_ver}.%{minor_ver}.%{update_num}
%define version %{package_version}
%define name srx-proxy-devel
%define core_name srx
%define _unpackaged_files_terminate_build 0
%define 

Name:%{name}
Version:%{version}
Release:1%{?dist}
Summary:Package provides the SRx Proxy developer files
Group:Networking/Daemons
License:https://www.nist.gov/director/copyright-fair-use-and-licensing-statements-srd-data-and-software
URL:https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype
Vendor:National Institute of Standards and Technology (NIST)
Distribution:NIST BGP-SRx Software Suite
Packager:BGP-SRx Dev <itrg-contact@list.nist.gov>

Source0:%{core_name}-%{version}.tar.gz
BuildRoot:/tmp/rpm/%{core_name}-%{version}

BuildRequires:automake	
Requires: %{core_name}-proxy = %{version}
  
%description
The SRx Proxy developers package

%prep
%setup -q -n %{core_name}-%{version}

%build

%install
# install the header files
mkdir -p $RPM_BUILD_ROOT/%{_includedir}/%{srxdir}
cat %{CLIENT_DIR}/srx_api.h | sed -e 's/^\(#include \"[a-z]\+\)\(.*\)\".*/#include <%{srxdir}\2>/g' > $RPM_BUILD_ROOT/%{_includedir}/%{srxdir}/srx_api.h
cat %{SHARED_DIR}/srx_defs.h | sed -e 's/^\(#include \"[a-z]\+\)\(.*\)\".*/#include <%{srxdir}\2>/g' > $RPM_BUILD_ROOT/%{_includedir}/%{srxdir}/srx_defs.h
cat %{UTIL_DIR}/prefix.h | sed -e 's/^\(#include \"[a-z]\+\)\(.*\)\".*/#include <%{srxdir}\2>/g' > $RPM_BUILD_ROOT/%{_includedir}/%{srxdir}/prefix.h
cat %{UTIL_DIR}/slist.h | sed -e 's/^\(#include \"[a-z]\+\)\(.*\)\".*/#include <%{srxdir}\2>/g' > $RPM_BUILD_ROOT/%{_includedir}/%{srxdir}/slist.h


%clean
rm -rf $RPM_BUILD_ROOT

%post

%preun

%postun
if [ "x$(ls -A %{_includedir}/%{srxdir})" = "x" ] ; then
  rmdir %{_includedir}/%{srxdir}
fi 

%files
#%defattr(644,root,root,755)
%defattr(-,root,root,-)
%{_includedir}/%{srxdir}/srx_defs.h
%{_includedir}/%{srxdir}/srx_api.h
%{_includedir}/%{srxdir}/slist.h
%{_includedir}/%{srxdir}/prefix.h
