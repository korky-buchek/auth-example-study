/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.web;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Daniel Garnier-Moiroux
 */
@Controller
public class AuthorizationConsentController {
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationConsentService authorizationConsentService;

	public AuthorizationConsentController(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationConsentService authorizationConsentService) {
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationConsentService = authorizationConsentService;
	}

	@GetMapping(value = "/oauth2/consent")
	public String consent(Principal principal, Model model,
			@RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
			@RequestParam(OAuth2ParameterNames.SCOPE) String scope,
			@RequestParam(OAuth2ParameterNames.STATE) String state,
			@RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode) {

		// Remove scopes that were already approved
		Set<String> scopesToApprove = new HashSet<>();
		Set<String> previouslyApprovedScopes = new HashSet<>();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		OAuth2AuthorizationConsent currentAuthorizationConsent =
				this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());
		Set<String> authorizedScopes;
		if (currentAuthorizationConsent != null) {
			authorizedScopes = currentAuthorizationConsent.getScopes();
		} else {
			authorizedScopes = Collections.emptySet();
		}
		for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
			if (OidcScopes.OPENID.equals(requestedScope)) {
				continue;
			}
			if (authorizedScopes.contains(requestedScope)) {
				previouslyApprovedScopes.add(requestedScope);
			} else {
				scopesToApprove.add(requestedScope);
			}
		}

		model.addAttribute("clientId", clientId);
		model.addAttribute("state", state);
		model.addAttribute("scopes", withDescription(scopesToApprove));
		model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
		model.addAttribute("principalName", principal.getName());
		model.addAttribute("userCode", userCode);
		if (StringUtils.hasText(userCode)) {
			model.addAttribute("requestURI", "/oauth2/device_verification");
		} else {
			model.addAttribute("requestURI", "/oauth2/authorize");
		}

		return "consent";
	}

	private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
		Set<ScopeWithDescription> scopeWithDescriptions = new HashSet<>();
		for (String scope : scopes) {
			scopeWithDescriptions.add(new ScopeWithDescription(scope));
		}
		return scopeWithDescriptions;
	}

	public static class ScopeWithDescription {
		private static final String DEFAULT_DESCRIPTION = "UNKNOWN SCOPE - We cannot provide information about this permission, use caution when granting this.";
		private static final String DEFAULT_FAMILAR_SCOPE = "알 수 없는 권한";

		private static final Map<String, String> familiarScopes = new HashMap<>();
		private static final Map<String, String> scopeDescriptions = new HashMap<>();
		static {
			familiarScopes.put(
					OidcScopes.PROFILE,
					"프로필 접근"
			);
			familiarScopes.put(
					"message.read",
					"메세지 읽기"
			);
			familiarScopes.put(
					"message.write",
					"메세지 쓰기"
			);
			familiarScopes.put(
					"other.scope",
					"기타"
			);
			scopeDescriptions.put(
					OidcScopes.PROFILE,
					"이 앱은 당신의 프로필 정보에 접근할 수 있습니다."
			);
			scopeDescriptions.put(
					"message.read",
					"앱이 당신의 메세지를 읽을 수 있습니다."
			);
			scopeDescriptions.put(
					"message.write",
					"앱이 메세지를 추가/수정/삭제 할 수 있습니다."
			);
			scopeDescriptions.put(
					"other.scope",
					"기타 접근에 허용합니다."
			);
		}

		public final String scope;
		public final String familiarScope;
		public final String description;

		ScopeWithDescription(String scope) {
			this.scope = scope;
			this.familiarScope = familiarScopes.getOrDefault(scope, DEFAULT_FAMILAR_SCOPE);
			this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
		}
	}

}
