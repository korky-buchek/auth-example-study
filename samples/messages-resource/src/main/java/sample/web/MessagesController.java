/*
 * Copyright 2020 the original author or authors.
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

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@RestController
public class MessagesController {

	private HashMap<String, String> Messages;

	public MessagesController(){
		Messages = new HashMap<>();
		Messages.put(UUID.randomUUID().toString(), "Message 1");
		Messages.put(UUID.randomUUID().toString(), "Message 3");
		Messages.put(UUID.randomUUID().toString(), "Message 2");
	}

	@GetMapping("/messages")
	public ResponseEntity<Map<String, String>> getMessages() {
//		return new String[] {"Message 1", "Message 2", "Message 3"};
		return new ResponseEntity<Map<String, String>>(Messages, HttpStatus.OK);
	}

	@GetMapping("/messages/add")
	public ResponseEntity<Void> addMessage(@RequestParam String message, Principal principal)
	{
		Messages.put(UUID.randomUUID().toString(), message);
		return ResponseEntity.ok().build();
	}

	@GetMapping("/messages/remove")
	public ResponseEntity<Void> removeMessage(@RequestParam String uuid, Principal principal)
	{
		Messages.remove(uuid);
		return ResponseEntity.ok().build();
	}
}
