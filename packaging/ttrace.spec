Name:		ttrace
Summary:    T-trace for tizen
Version:	1.0.0
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
SOURCE101:	packaging/exec-ttrace-marker
SOURCE102:	packaging/ttrace-marker.service
SOURCE103:	packaging/atrace-bootup.sh

BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(zlib)
BuildRequires: pkgconfig(capi-base-common)
BuildRequires: cmake

%define keepstatic 1

%define TTRACE_PROFILE none
%if "%{?tizen_profile_name}" == "mobile"
%define TTRACE_PROFILE mobile
%else
%if "%{?tizen_profile_name}" == "tv"
%define TTRACE_PROFILE tv
%else
%if "%{?tizen_profile_name}" == "wearable"
%define TTRACE_PROFILE wearable
%endif
%endif
%endif

%description
T-trace library

%package devel
Summary:    T-trace for tizen
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
T-trace library devel

%prep
%setup -q

%build
export CFLAGS="$CFLAGS -g -Wall -std=gnu99"
export CXXFLAGS="$CXXFLAGS -std=c++0x -fPIE -pie"
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DLIBDIR=%{_libdir} -DINCLUDEDIR=%{_includedir}
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
install -d %{buildroot}%{_unitdir}/ttrace-marker.service.wants
install -m0644 %{SOURCE102} %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_bindir}
cp %{SOURCE101} %{buildroot}%{_bindir}
cp %{SOURCE103} %{buildroot}%{_bindir}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
%install_service sys-kernel-debug.mount.wants ttrace-marker.service

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest ttrace.manifest
%defattr(-,root,root,-)
%{_libdir}/libttrace.so.*
%{_unitdir}/ttrace-marker.service
%{_unitdir}/ttrace-marker.service.wants/
%attr(755,root,developer) %{_bindir}/atrace
%attr(755,root,developer) %{_bindir}/atrace-1.1
%attr(755,root,root) %{_bindir}/exec-ttrace-marker
%{_unitdir}/sys-kernel-debug.mount.wants/ttrace-marker.service
%attr(755,root,root) %{_bindir}/atrace-bootup.sh
/usr/share/license/%{name}

%files devel
%defattr(-,root,root,-)
%{_includedir}/ttrace.h
%{_includedir}/TTraceWrapper.h
%{_includedir}/trace.h
%{_libdir}/libttrace.so
%{_libdir}/libttrace.a
%{_libdir}/pkgconfig/ttrace.pc
%{_libdir}/pkgconfig/ttrace-static.pc
%{_libdir}/pkgconfig/atrace.pc
