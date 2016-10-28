Name:		ttrace
Summary:    T-trace for tizen
Version:	1.0.0
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
SOURCE102:	packaging/ttrace-marker.service
SOURCE103:	packaging/atrace-bootup.sh

BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(zlib)
BuildRequires: pkgconfig(capi-base-common)
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(ttrace-extension-static)
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

%define TTRACE_TIZEN_VERSION_MAJOR 2
%if "%{?tizen_version_major}" == "3"
%define TTRACE_TIZEN_VERSION_MAJOR 3
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
export CFLAGS="$CFLAGS -flto -g -Wall -std=gnu99"
export CXXFLAGS="$CXXFLAGS -flto -std=c++0x -fPIE -pie"
%cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DLIBDIR=%{_libdir} -DINCLUDEDIR=%{_includedir} \
      -DTTRACE_PROFILE=%{TTRACE_PROFILE} -DTTRACE_TIZEN_VERSION_MAJOR=%{TTRACE_TIZEN_VERSION_MAJOR}
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install
install -d %{buildroot}%{_unitdir}/ttrace-marker.service.wants
install -m0644 %{SOURCE102} %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_bindir}
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
%attr(755,root,users) %{_bindir}/atrace
%attr(755,root,users) %{_bindir}/atrace-1.1
%{_unitdir}/sys-kernel-debug.mount.wants/ttrace-marker.service
%attr(755,root,root) %{_bindir}/atrace-bootup.sh
/usr/share/license/%{name}

%files devel
%defattr(-,root,root,-)
%{_includedir}/*.h
%{_libdir}/libttrace.so
%{_libdir}/libttrace.a
%{_libdir}/pkgconfig/*.pc
