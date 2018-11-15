Summary: Pacrunner javascript plugin using QJsEngine
Name: pacrunner-cutes
Version: 0.0.1
Release: 1
License: GPLv2
Group: Development/Liraries
URL: https://git.merproject.org/mer-core/pacrunner-cutes
Source0: %{name}-%{version}.tar.bz2
BuildRequires: cmake >= 2.8
BuildRequires: pkgconfig(pacrunner-1.0)
BuildRequires: pkgconfig(Qt5Core)
BuildRequires: pkgconfig(Qt5Qml)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(tut) >= 0.0.1
%description
%{summary}

%package tests
Summary:    Tests for pacrunner-cutes
Group:      System Environment/Libraries
Requires:   %{name} = %{version}-%{release}

%description tests
%summary

%prep
%setup -q

%build
%cmake %{?_with_multiarch:-DENABLE_MULTIARCH=ON}
make %{?jobs:-j%jobs}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=%{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/pacrunner/plugins/libpacrunner-cutes.so
%{_datadir}/pacrunner/pacrunner.js

%files tests
%defattr(-,root,root,-)
/opt/tests/pacrunner-cutes/*
