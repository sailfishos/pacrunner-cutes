/*
 *
 *  PACrunner - Proxy configuration daemon
 *
 *  Copyright (C) 2010  Intel Corporation. All rights reserved.
 *  Copyright (C) 2014  Jolla Ltd. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

#include <glib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>

extern "C" {
#include "plugin.h"
#include "js.h"
};

#include "config.hpp"

#include <QJSEngine>

#include <QQmlEngine>
#include <QFile>
#include <QCoreApplication>
#include <QDebug>

#include <memory>
#include <mutex>
#include <iostream>

#define CERR()  std::cerr << __PRETTY_FUNCTION__
#ifdef DEBUG
#define DBG() CERR() << std::endl;
#else
#define DBG() CERR()
#endif

#define PLUGIN_NAME "cutes"

// TODO it should be in pacrunner public headers
extern "C" const char *pacrunner_proxy_get_script(struct pacrunner_proxy *proxy);
extern "C" const char *pacrunner_proxy_get_interface(struct pacrunner_proxy *proxy);

template <typename T, typename ... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}


class Engine : public QObject
{
    Q_OBJECT
public:
    Engine()
        : engine_(mk_engine())
    {
        auto functions_ = engine_->newQObject(this);
        QQmlEngine::setObjectOwnership(this, QQmlEngine::CppOwnership);
        engine_->globalObject().setProperty("myIpAddress", functions_.property("myIpAddress"));
        engine_->globalObject().setProperty("dnsResolve", functions_.property("dnsResolve"));
    }

    Q_INVOKABLE QString myIpAddress();
    Q_INVOKABLE QString dnsResolve(const QString &);

    static int set_proxy(struct pacrunner_proxy *proxy);
    static char * execute(const char *url, const char *host);

private:
    std::unique_ptr<QJSEngine> mk_engine();

    static void create_object();
    void mk_find_proxy(char const *);
    QString find_proxy(const char *url, const char *host);

    static int argc_;
    static char* argv_[];
    static std::mutex mutex_;
    static struct pacrunner_proxy *current_proxy_;
    static std::unique_ptr<Engine> instance_;

    std::list<std::function<void()> > on_delete_;
    QCoreApplication *app_;
    std::unique_ptr<QJSEngine> engine_;
    QJSValue find_proxy_;
};

int Engine::argc_ = 1;
char* Engine::argv_[] = {NULL};
std::mutex Engine::mutex_;
struct pacrunner_proxy *Engine::current_proxy_ = nullptr;
std::unique_ptr<Engine> Engine::instance_;

std::unique_ptr<QJSEngine> Engine::mk_engine()
{
    DBG();
    app_ = QCoreApplication::instance();
    if (!app_) {
        argv_[0] = strdup(PLUGIN_NAME);
        app_ = new QCoreApplication(argc_, argv_);
        on_delete_.push_back([this]() {
                free(argv_[0]);
                delete app_;
            });
    }
    return make_unique<QJSEngine>();
}

void Engine::create_object()
{
    DBG();
    if (instance_)
        return;

	if (!current_proxy_)
		return;

	const char *pac = pacrunner_proxy_get_script(current_proxy_);
	if (!pac) {
		printf("no script\n");
		return;
	}

    if (!instance_)
        instance_ = make_unique<Engine>();
    instance_->mk_find_proxy(pac);
}

void Engine::mk_find_proxy(char const *pac)
{
    DBG();
    QFile js_file(PACRUNNER_JS_FILE);
    if (!js_file.open(QIODevice::ReadOnly)) {
        qWarning() << "Can't open " << PACRUNNER_JS_FILE;
        return;
    }
    QString code(js_file.readAll());
    js_file.close();
	auto script_scr = engine_->evaluate(code);
	if (script_scr.isError()) {
		qWarning() << "Javascript failed to compile: " << script_scr.toString();
		return;
	}

	script_scr = engine_->evaluate(pac);
	if (script_scr.isError()) {
		qWarning() << "PAC script failed to compile: " << script_scr.toString();
		return;
	}

	auto const &globals = engine_->globalObject();
    find_proxy_ = globals.property("FindProxyForURL");
    if (!find_proxy_.isCallable())
		qWarning() << "FindProxyForUrl is not a function";
}

static int getaddr(const char *node, char *host, size_t hostlen)
{
    DBG();
	struct sockaddr_in addr;
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, node, sizeof(ifr.ifr_name));

	err = ioctl(sk, SIOCGIFADDR, &ifr);

	close(sk);

	if (err < 0)
		return -EIO;

	memcpy(&addr, &ifr.ifr_addr, sizeof(addr));
	snprintf(host, hostlen, "%s", inet_ntoa(addr.sin_addr));

	return 0;
}

static int resolve(const char *node, char *host, size_t hostlen)
{
    DBG();
	struct addrinfo *info;
	int err;

	if (getaddrinfo(node, NULL, NULL, &info) < 0)
		return -EIO;

	err = getnameinfo(info->ai_addr, info->ai_addrlen,
				host, hostlen, NULL, 0, NI_NUMERICHOST);

	freeaddrinfo(info);

	if (err < 0)
		return -EIO;

	return 0;
}

QString Engine::myIpAddress()
{
    DBG();
	const char *interface;
	char address[NI_MAXHOST];

	if (!current_proxy_) {
        qWarning() << "No current proxy";
		// TODO return env->throwException("No current proxy");
        return QString();
    }

	interface = pacrunner_proxy_get_interface(current_proxy_);
	if (interface == NULL) {
        qWarning() << "Error fetching interface";
        return QString();
		// TODO return env->throwException("Error fetching interface");
    }

	if (getaddr(interface, address, sizeof(address)) < 0) {
        qWarning() << "Error fetching IP address";
        return QString();
		// TODO return env->throwException("Error fetching IP address");
    }

	return address;
}

QString Engine::dnsResolve(const QString &host)
{
	char address[NI_MAXHOST];

	if (resolve(host.toUtf8().constData(), address, sizeof(address)) < 0) {
        qWarning() << "Failed to resolve";
        return QString();
		// TODO return env_->throwException("Failed to resolve");
    }

	return QString(address);
}

int Engine::set_proxy(struct pacrunner_proxy *proxy)
{
    DBG();
    try {
        std::lock_guard<std::mutex> lock_(mutex_);
        if (current_proxy_)
            instance_.reset();
        current_proxy_ = proxy;
        Engine::create_object();
    } catch (...) {
        CERR() << "Caught c++ exception\n";
        return -1;
    }
    return 0;
}

QString Engine::find_proxy(const char *url, const char *host)
{
    DBG();
	if (!find_proxy_.isCallable()) {
        qWarning() << "FindProxyForUrl is not resolved";
		return QString();
    }

    QJSValueList params;
    params.push_back(QString(url));
    params.push_back(QString(host));

    auto result = find_proxy_.call(params);
	if (result.isError()) {
		qWarning() << "Failed to run FindProxyForUrl(): ", result.toString();
		return QString();
	}

	if (!result.isString()) {
		qWarning() << "FindProxyForUrl() failed to return a string, got "
                   << result.toString();
		return QString();
	}
    return result.toString();
};

char * Engine::execute(const char *url, const char *host)
{
    DBG();
    try {
        std::lock_guard<std::mutex> lock_(mutex_);
        if (!instance_)
            return nullptr;

        auto res = instance_->find_proxy(url, host);
        if (res.isNull())
            return nullptr;

        return g_strdup(res.toUtf8().constData());
    } catch (...) {
        CERR() << "Caught c++ exception\n";
        return nullptr;
    }
}

static struct pacrunner_js_driver cutes_driver = {
	PLUGIN_NAME,
	PACRUNNER_JS_PRIORITY_HIGH,
	&Engine::set_proxy,
	&Engine::execute,
};

static int cutes_init(void)
{
    DBG();
	return pacrunner_js_driver_register(&cutes_driver);
}

static void cutes_exit(void)
{
    DBG();
	pacrunner_js_driver_unregister(&cutes_driver);
    Engine::set_proxy(nullptr);
}

PACRUNNER_PLUGIN_DEFINE(cutes, cutes_init, cutes_exit)

#include "pacrunner.moc"
