package sample.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.Principal;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
public class MessageController {

	private final WebClient webClient;
	private final String messagesBaseUri;

	public MessageController(WebClient webClient,
			@Value("http://127.0.0.1:8090/messages") String messagesBaseUri) {
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
	}

	@GetMapping(value = "/messages/add", params="grant_type=client_credentials")
	public ResponseEntity<Void> addMessage(Model model, @RequestParam String message, Principal principal)
	{
		var result = webClient.get()
					.uri(this.messagesBaseUri + "/add?message=" + message)
					.attributes(clientRegistrationId("messaging-client-client-credentials"))
					.retrieve().toEntity(Void.class).block();

		return ResponseEntity.ok().build();
	}
	@GetMapping(value = "/messages/add", params="grant_type=authorization_code")
	public ResponseEntity<Void> addMessage(Model model, @RequestParam String message, @RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
	OAuth2AuthorizedClient authorizedClient, Principal principal)
	{
		var scopes = authorizedClient.getClientRegistration().getScopes();
		if (scopes.contains("message.write"))
		{
			var result = webClient.get()
					.uri(this.messagesBaseUri + "/add?message=" + message)
					.attributes(oauth2AuthorizedClient(authorizedClient))
					.retrieve().toEntity(Void.class).block();
		}

		return ResponseEntity.ok().build();
	}

	@GetMapping(value="/messages/remove", params="grant_type=client_credentials")
	public ResponseEntity<Void> removeMessage(Model model, @RequestParam String uuid, Principal principal){
		var isAdmin = "ROLE_ADMIN".equals(((OAuth2AuthenticationToken) principal).getPrincipal().getAttribute("role"));
		if (isAdmin) {
			webClient.get()
					.uri(this.messagesBaseUri + "/remove?uuid=" + uuid)
					.attributes(clientRegistrationId("messaging-client-client-credentials"))
					.retrieve()
					.toEntity(Void.class)
					.block();
		}
		return ResponseEntity.ok().build();
	}

	@GetMapping(value="/messages/remove", params="grant_type=authorization_code")
	public ResponseEntity<Void> removeMessage(Model model, @RequestParam String uuid,
			@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code") OAuth2AuthorizedClient authorizedClient,
			Principal principal){
		var isAdmin = "ROLE_ADMIN".equals(((OAuth2AuthenticationToken) principal).getPrincipal().getAttribute("role"));
		var scopes = authorizedClient.getClientRegistration().getScopes();
		if (isAdmin)
		{
			var result = webClient.get()
					.uri(this.messagesBaseUri + "/remove?uuid=" + uuid)
					.attributes(oauth2AuthorizedClient(authorizedClient))
					.retrieve().toEntity(Void.class).block();
		}
		return ResponseEntity.ok().build();
	}
}
