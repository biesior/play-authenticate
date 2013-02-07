package security;

import com.avaje.ebean.Ebean;
import com.avaje.ebean.SqlUpdate;
import com.feth.play.module.pa.PlayAuthenticate;
import models.AuthenticateSession;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;

import play.Configuration;
import play.Play;
import play.cache.Cache;
import play.mvc.Http;

import java.util.ArrayList;
import java.util.List;

import static play.Logger.debug;
import static play.Logger.info;
import static play.mvc.Http.Context;
import static play.mvc.Http.Request;
import static play.mvc.Http.Session;

public class PaSession {


    private static final Configuration PA_CONF = PlayAuthenticate.getConfiguration();
    public static final boolean DB_STORAGE = (PA_CONF.getBoolean("session.dbStorage") != null && PA_CONF.getBoolean("session.dbStorage")) ? true : false;
    private static final boolean DISABLE_CHECK_IN_DEV = (Play.isDev()
            && PA_CONF.getBoolean("session.disableCheckInDev") != null
            && PA_CONF.getBoolean("session.disableCheckInDev")) ? true : false;

    public static final boolean CLEAR_ON_START = PA_CONF.getBoolean("session.clearOnStart");
    public static final int CLEAR_FREQUENCY = PA_CONF.getInt("session.clearFrequency");

    public static final String SES_KEY = "pa.ses.id";
    public static final String EXPIRES_KEY = "pa.u.exp";
    public static final String USER_KEY = "pa.u.id";
    private static final String CACHE_PREFIX = "PA_SES_";


    public String sesId;
    public String ipLock;
    public String userId;
    public String hash;
    private boolean storedInDb;
    private Long dbId;
    private Context context;


    /**
     * Creates session with new id
     *
     * @param session Session
     * @param request Request
     */
    public PaSession(Session session, Request request) {
        this(session, request, RandomStringUtils.randomAlphanumeric(64));
    }

    /**
     * Creates session from context (for comparison)
     *
     * @param ctx Context (contains session and request)
     */
    public PaSession(Context ctx) {
        this(ctx.session(), ctx.request(), ctx.session().get(SES_KEY));
        this.context = ctx;
    }

    public PaSession(Session session, Request request, String sesId) {

        this.sesId = sesId;
        this.userId = session.get(USER_KEY);
        this.ipLock = createIpLock(request);

        calculateHash();
    }

    private void calculateHash() {
        this.hash = DigestUtils.sha256Hex("ses_hash_" + this.sesId + "_" + this.sesId + this.userId + this.ipLock);
    }


    private String createIpLock(Request request) {
        int ipLockSize = PA_CONF.getInt("session.ipLockSize");
        if (ipLockSize == 0) return "";


        String ipAddress = (PA_CONF.getBoolean("session.useForwardIp")
                && request.getHeader(PA_CONF.getString("session.forwardIpHeader")) != null)
                ? request.getHeader(PA_CONF.getString("session.forwardIpHeader"))
                : request.remoteAddress();

        List<String> parts = new ArrayList<String>();

        String ipLockParts[] = ipAddress.split("\\.");
        int i = 0;
        for (String part : ipLockParts) {
            if (i < ipLockSize) parts.add(part);
            i++;
        }

        return StringUtils.join(parts, ".");
    }


    public void saveToCache(Session session) {
        String newExpDate = getExpDate();

        if (DB_STORAGE) {
            AuthenticateSession dbSes = AuthenticateSession.find.select("sesId").where().eq("sesId", this.sesId).findUnique();
            if (dbSes == null) {
                dbSes = new AuthenticateSession(this, newExpDate);
                dbSes.save();
            } else {
                dbSes.expDate = newExpDate;
                dbSes.update(dbSes.id);
            }
            this.dbId = dbSes.id;
        }
        Cache.set(CACHE_PREFIX + this.sesId, this, PA_CONF.getInt("session.timeout"));
        session.put(EXPIRES_KEY, newExpDate);
        session.put(SES_KEY, this.sesId);

    }

    public static void delete(Session session) {
        String cacheKey = CACHE_PREFIX + session.get(SES_KEY);
        Cache.set(cacheKey, null, 0);

        if (DB_STORAGE) {
            AuthenticateSession dbSes = AuthenticateSession.find.select("id").where().eq("sesId", session.get(SES_KEY)).findUnique();
            if (dbSes != null) dbSes.delete();
        }
        session.remove(SES_KEY);
    }

    public boolean exists() {

        if (DISABLE_CHECK_IN_DEV) return true;

        String cacheKey = CACHE_PREFIX + this.context.session().get(SES_KEY);
        PaSession cachedSession = (PaSession) Cache.get(cacheKey);
        boolean exists;
        if (cachedSession != null && this.hash.equals(cachedSession.hash)) {
            this.saveToCache(this.context.session());
            exists = true;
        } else if (existsInDb(this.context.session())) {
            this.saveToCache(this.context.session());
            exists = true;
        } else {
            exists = false;
            delete(this.context.session());
            com.feth.play.module.pa.controllers.Authenticate.logout();
        }
        return exists;
    }

    private boolean existsInDb(Session session) {

        if (DB_STORAGE) {
            AuthenticateSession dbSes = AuthenticateSession.find.select("id, expDate").where().eq("sesId", session.get(SES_KEY)).findUnique();
            if (dbSes != null) {
                if (System.currentTimeMillis() < Long.valueOf(dbSes.expDate)) {
                    return true;
                } else {
                    dbSes.delete();
                    return false;
                }
            }
        }

        return false;
    }

    public String getExpDate() {
        int timeout = PA_CONF.getInt("session.timeout");
        String out = "-1";
        if (timeout > 0) {
            Long ts = (System.currentTimeMillis()) + (timeout * 1000);
            out = ts.toString();
        }
        return out;
    }

    public static void clearTerminatedSessions() {
       Ebean.createSqlUpdate("DELETE FROM AUTHENTICATE_SESSION WHERE exp_date < " + (System.currentTimeMillis() - 1000)).execute();
    }
}
