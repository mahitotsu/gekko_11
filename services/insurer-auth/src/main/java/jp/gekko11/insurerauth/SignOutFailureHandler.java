package jp.gekko11.insurerauth;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * サインアウトの要求の ID トークンを確かめられないときの応答（D-33）。例えば、再起動の前に出した ID トークンである。
 * 標準の応答は 400 のエラー画面で、ログインの画面へ送られ、利用者はアプリへ戻れない。そこで、そのクライアントに登録された戻り先へ戻す。
 * 登録にない宛先へは戻さない（任意のサイトへ送る踏み台にしない）。認可サーバーのログインは終わらせない。
 */
final class SignOutFailureHandler implements AuthenticationFailureHandler {

	private final RegisteredClientRepository clients;

	SignOutFailureHandler(RegisteredClientRepository clients) {
		this.clients = clients;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {
		String clientId = request.getParameter("client_id");
		String target = request.getParameter("post_logout_redirect_uri");
		RegisteredClient client = (clientId == null) ? null : this.clients.findByClientId(clientId);
		if (client != null && target != null && client.getPostLogoutRedirectUris().contains(target)) {
			response.sendRedirect(target);
			return;
		}
		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
		response.setContentType("text/plain;charset=UTF-8");
		response.getWriter().write("サインアウトの要求を確かめられません。");
	}

}
