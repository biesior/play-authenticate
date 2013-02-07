package models;

import play.db.ebean.Model;
import play.mvc.Http;
import security.PaSession;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class AuthenticateSession extends Model {

    private static final long serialVersionUID = 1L;

    @Id
    public Long id;

    public String sesId;
    public String ipLock;
    public String userId;
    public String hash;
    public String expDate;


    public static Finder<Long, AuthenticateSession> find
            = new Finder<Long, AuthenticateSession>(Long.class, AuthenticateSession.class);


    public AuthenticateSession(PaSession paSession, String newExpDate) {
        this.sesId = paSession.sesId;
        this.ipLock = paSession.ipLock;
        this.userId = paSession.userId;
        this.hash = paSession.hash;
        this.expDate = newExpDate;
    }
}
