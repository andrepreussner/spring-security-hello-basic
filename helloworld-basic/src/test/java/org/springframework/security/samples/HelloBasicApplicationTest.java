package org.springframework.security.samples;

import static org.hamcrest.CoreMatchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class HelloBasicApplicationTest {

	@Autowired
	private MockMvc mockMvc;

	/**
	 * Test that session fixation protection works for Basic Auth.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSessionFixationProtectionForBasicAuth() throws Exception {
		final SessionHolder sessionHolder = new SessionHolder();

		// login with "user" and store session
		this.mockMvc.perform(get("/user").with(httpBasic("user", "user"))).andExpect(status().isOk())
				.andDo((result) -> {
					sessionHolder.session = (MockHttpSession) result.getRequest().getSession(false);
				});
		Assert.assertNotNull(sessionHolder.session);
		String userSessionId = sessionHolder.session.getId();

		// to make sure that session is working correctly, check reading user endpoint is ok
		this.mockMvc.perform(get("/user").with((request) -> {
			request.setSession(sessionHolder.session);
			return request;
		})).andExpect(status().isOk());

		// to make sure that session is working correctly, check reading admin endpoint is
		// forbidden (logged in as "user")
		this.mockMvc.perform(get("/admin").with((request) -> {
			request.setSession(sessionHolder.session);
			return request;
		})).andExpect(status().isForbidden());

		// session fixation attack: login with basic auth from "admin" and with session
		// from "user"
		this.mockMvc.perform(get("/admin").with(httpBasic("admin", "admin")).with((request) -> {
			request.setSession(sessionHolder.session);
			return request;
		})).andExpect(status().isOk());

		Assert.assertEquals(userSessionId, sessionHolder.session.getId());
		// expect the "user" session to still not being allowed to access "admin" endpoint;
		// actually it should either be HTTP 401 (session has been invalidated) or HTTP
		// 403 (session is still a user session and not allowed to access admin endpoint),
		// but checking for being not HTTP 200 is sufficient for our purpose
		this.mockMvc.perform(get("/admin").with((request) -> {
			request.setSession(sessionHolder.session);
			return request;
		})).andExpect(status().is(not(200)));
	}

	/**
	 * Test that session fixation protection works for anonymous user.
	 *
	 * @throws Exception
	 */
	@Test
	public void testSessionFixationProtectionForAnonymous() throws Exception {
		final SessionHolder sessionHolder = new SessionHolder();

		// login with "user" and store session
		this.mockMvc.perform(get("/")).andExpect(status().isOk())
		.andDo((result) -> {
			sessionHolder.session = (MockHttpSession) result.getRequest().getSession(false);
		});
		Assert.assertNotNull(sessionHolder.session);
		String anonymousSessionId = sessionHolder.session.getId();

		// to make sure that session is working correctly, check reading user endpoint is ok
		this.mockMvc.perform(get("/user").with((request) -> {
			request.setSession(sessionHolder.session);
			return request;
		})).andExpect(status().isUnauthorized());

		// to make sure that session is working correctly, check reading admin endpoint is
		// forbidden (logged in as "user")
		this.mockMvc.perform(get("/admin").with((request) -> {
			request.setSession(sessionHolder.session);
			return request;
		})).andExpect(status().isUnauthorized());

		final SessionHolder adminSession = new SessionHolder();
		// session fixation attack: login with basic auth from "admin" and with session
		// from "user"
		this.mockMvc.perform(get("/admin").with(httpBasic("admin", "admin")).with((request) -> {
			request.setSession(sessionHolder.session);
			return request;
		})).andExpect(status().isOk())
		.andDo((result) -> {
			adminSession.session = (MockHttpSession) result.getRequest().getSession(false);
		});;

		Assert.assertEquals(anonymousSessionId, sessionHolder.session.getId());
		// expect the "user" session to still not being allowed to access "admin" endpoint;
		// actually it should either be HTTP 401 (session has been invalidated) or HTTP
		// 403 (session is still a user session and not allowed to access admin endpoint),
		// but checking for being not HTTP 200 is sufficient for our purpose
		this.mockMvc.perform(get("/admin").with((request) -> {
			request.setSession(sessionHolder.session);
			return request;
		})).andExpect(status().is(not(200)));
	}

	private class SessionHolder {
		public MockHttpSession session;
	}
}
