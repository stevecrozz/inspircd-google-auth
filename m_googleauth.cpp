/* +------------------------------------+
 * | Inspire Internet Relay Chat Daemon |
 * +------------------------------------+
 *
 * inspirecd-google-auth: (C) 2011 Stephen Crosby
 *
 * ---------------------------------------------------
 */

#include "inspircd.h"
#include <curl/curl.h>
#include <algorithm.h>
#include "hash.h"

#define GOOGLE_AUTH_URL "https://www.google.com/accounts/ClientLogin"
#define GOOGLE_AUTH_SERVICE "cp"
#define USER_AGENT "Inspircd"

/* $ModDesc: Allow/Deny connections based on google account authentication */
/* $CompileFlags: exec("curl-config --cflags") */
/* $LinkerFlags: -lcurl */

enum AuthState {
	AUTH_STATE_NONE = 0,
	AUTH_STATE_BUSY = 1,
	AUTH_STATE_FAIL = 2
};

size_t curlWriteCallback(char* buf, size_t size, size_t nmemb, void* up)
{
	return size*nmemb; //tell curl how many bytes we handled
}

class ModuleGoogleAuth : public Module
{
	LocalIntExt pendingExt;
	std::string domainrestriction;
	std::string killreason;
	std::string authresponse;
	bool verbose;

 public:
	ModuleGoogleAuth() : pendingExt("googleauth-wait", this)
	{
	}

	void init()
	{
		ServerInstance->Modules->AddService(pendingExt);
		OnRehash(NULL);
		Implementation eventlist[] = { I_OnUserDisconnect, I_OnCheckReady, I_OnRehash, I_OnUserRegister };
		ServerInstance->Modules->Attach(eventlist, this, 4);
	}

	void OnRehash(User* user)
	{
		ConfigTag* conf = ServerInstance->Config->ConfValue("googleauth");
		domainrestriction = conf->getString("domainrestriction");
		killreason = conf->getString("killreason");
		verbose = conf->getBool("verbose");
	}

	ModResult OnUserRegister(LocalUser* user)
	{
		// Note this is their initial (unresolved) connect block
		ConfigTag* tag = user->MyClass->config;
		if (!tag->getBool("googleauth", true))
			return MOD_RES_PASSTHRU;

		if (pendingExt.get(user))
			return MOD_RES_PASSTHRU;

		if (user->password.empty()) {
			if (verbose)
				ServerInstance->SNO->WriteToSnoMask('c', "Forbidden connection from %s!%s@%s (No password provided)", user->nick.c_str(), user->ident.c_str(), user->host.c_str());

			pendingExt.set(user, AUTH_STATE_FAIL);
			return MOD_RES_PASSTHRU;
		}

		std::string googleAccountName = user->nick;
		std::replace(googleAccountName.begin(), googleAccountName.end(), '_', '.');
		if (!domainrestriction.empty()) {
			googleAccountName += "@" + domainrestriction;
		} else {
			return MOD_RES_PASSTHRU;
		}

		CURL *curl;
		CURLcode curl_code;
		curl = curl_easy_init();
		long http_code = 0;

		std::string queryParameters = "";
		queryParameters += "Email=";
		queryParameters += curl_easy_escape(curl, googleAccountName.c_str(),	strlen(googleAccountName.c_str()));
		queryParameters += "&Passwd=";
		queryParameters += curl_easy_escape(curl, user->password.c_str(), strlen(user->password.c_str()));
		queryParameters += "&accountType=GOOGLE";
		queryParameters += "&source=";
		queryParameters += USER_AGENT;
		queryParameters += "&service=";
		queryParameters += GOOGLE_AUTH_SERVICE;

		if (verbose)
			ServerInstance->SNO->WriteToSnoMask('c', "Attempting to authenticate '%s' with google...", googleAccountName.c_str());

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt(curl, CURLOPT_URL, GOOGLE_AUTH_URL);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, queryParameters.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(queryParameters.c_str()));
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);

		curl_code = curl_easy_perform(curl);
		curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
		curl_easy_cleanup(curl);

		pendingExt.set(user, AUTH_STATE_BUSY);

		if (http_code == 200 && curl_code != CURLE_ABORTED_BY_CALLBACK) {
			pendingExt.set(user, AUTH_STATE_NONE);
		} else {
			pendingExt.set(user, AUTH_STATE_FAIL);
		}

		return MOD_RES_PASSTHRU;
	}

	ModResult OnCheckReady(LocalUser* user)
	{
		switch (pendingExt.get(user))
		{
			case AUTH_STATE_NONE:
				return MOD_RES_PASSTHRU;
			case AUTH_STATE_BUSY:
				return MOD_RES_DENY;
			case AUTH_STATE_FAIL:
				ServerInstance->Users->QuitUser(user, killreason);
				return MOD_RES_DENY;
		}
		return MOD_RES_PASSTHRU;
	}

	Version GetVersion()
	{
		return Version("Allow/Deny connections based on google account authentication.", VF_VENDOR);
	}
};

MODULE_INIT(ModuleGoogleAuth)
