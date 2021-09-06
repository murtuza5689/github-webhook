package com.example.webhook.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.HmacUtils;

import java.security.MessageDigest;

@RestController
@RequestMapping("/payload")
@Slf4j
public class WebhookEventController {

	private static final String EOL = "\n";

	@PostMapping
	public ResponseEntity<String> collapseEvent(
			@RequestHeader("X-Hub-Signature") String signature,
			@RequestBody String payload) {

		log.info("payload received");
		HttpHeaders headers = new HttpHeaders();
		headers.add("X-Github-Webhook-Client-Version", "version");

		if (signature == null) {
			return new ResponseEntity<>("No signature given.", headers, HttpStatus.BAD_REQUEST);
		}

		String computed = String.format("sha1=%s", HmacUtils.hmacSha1Hex("murtuzatest1", payload));

		if (!MessageDigest.isEqual(signature.getBytes(), computed.getBytes())) {
			return new ResponseEntity<>("Invalid signature.", headers, HttpStatus.UNAUTHORIZED);
		}

		int bytes = payload.getBytes().length;
		StringBuilder message = new StringBuilder();
		message.append("Signature OK.").append(EOL);

		message.append(String.format("Received %d bytes.", bytes)).append(EOL);
		return new ResponseEntity<>(message.toString(), headers, HttpStatus.OK);

	}
}
