import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import akka.util.Duration;
import models.SecurityRole;

import com.feth.play.module.pa.PlayAuthenticate;
import com.feth.play.module.pa.PlayAuthenticate.Resolver;
import com.feth.play.module.pa.exceptions.AccessDeniedException;
import com.feth.play.module.pa.exceptions.AuthException;

import controllers.routes;

import play.Application;
import play.GlobalSettings;
import play.libs.Akka;
import play.mvc.Call;
import security.PaSession;

public class Global extends GlobalSettings {

	public void onStart(Application app) {

        if (PaSession.DB_STORAGE && PaSession.CLEAR_ON_START) {
            PaSession.clearTerminatedSessions();
        }

        if (PaSession.DB_STORAGE && PaSession.CLEAR_FREQUENCY > 0) {
            Akka.system().scheduler().schedule(
                    Duration.create(0, TimeUnit.MILLISECONDS),
                    Duration.create(PaSession.CLEAR_FREQUENCY, TimeUnit.SECONDS),
                    new Runnable() {
                        @Override
                        public void run() {
                            PaSession.clearTerminatedSessions();
                        }
                    }
            );
        }

		PlayAuthenticate.setResolver(new Resolver() {

			@Override
			public Call login() {
				// Your login page
				return routes.Application.login();
			}

			@Override
			public Call afterAuth() {
				// The user will be redirected to this page after authentication
				// if no original URL was saved
				return routes.Application.index();
			}

			@Override
			public Call afterLogout() {
				return routes.Application.index();
			}

			@Override
			public Call auth(final String provider) {
				// You can provide your own authentication implementation,
				// however the default should be sufficient for most cases
				return routes.Application.authenticate(provider);
			}

			@Override
			public Call askMerge() {
				return routes.Account.askMerge();
			}

			@Override
			public Call askLink() {
				return routes.Account.askLink();
			}

			@Override
			public Call onException(final AuthException e) {
				if (e instanceof AccessDeniedException) {
					return routes.Signup
							.oAuthDenied(((AccessDeniedException) e)
									.getProviderKey());
				}

				// more custom problem handling here...
				return super.onException(e);
			}
		});

		initialData();
	}

	private void initialData() {
		if (SecurityRole.find.findRowCount() == 0) {
			for (final String roleName : Arrays
					.asList(controllers.Application.USER_ROLE)) {
				final SecurityRole role = new SecurityRole();
				role.roleName = roleName;
				role.save();
			}
		}
	}
}