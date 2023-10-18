/**
 * 
 */
package com.sabari.user;


import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.List;

import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;
import org.neo4j.driver.Query;
import org.neo4j.driver.Session;
import org.neo4j.driver.types.MapAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import static org.neo4j.driver.Values.parameters;

import java.util.ArrayList;
import java.util.Date;

public class CustomUserStorageProvider implements UserStorageProvider, 
  UserLookupProvider, 
  CredentialInputValidator,
  UserRegistrationProvider,
  UserQueryProvider {
    
    private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProvider.class);
    private KeycloakSession ksession;
    private ComponentModel model;

    public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
        this.ksession = ksession;
        this.model = model;
    }

    @Override
    public void close() {
        log.info("close()");
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        log.info("getUserById({})",id);
        StorageId sid = new StorageId(id);
        return getUserByUsername(realm, sid.getExternalId());
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserModel userModel;
        try (Session c = DbUtil.getSession(this.model)) {
            userModel = c.executeWrite(tx -> {
            var query 
                = new Query(CustomUserStorageProviderConstants.QUERY_GET_USER_INFO_BY_NAME,
                parameters(CustomUserStorageProviderConstants.DB_KEY_USER_NAME, username));
            var result = tx.run(query).list();
            if (result.size() == 1){
                return mapUser(realm, result.get(0));
            }
            return null;
          });
       }
       catch(Exception ex) {
           log.warn("Database error: unable to fetch record by username; ex={}", ex.getMessage());
           throw new RuntimeException("Database error: unable to fetch record by username",ex);
       }
       log.info("getUserByUsername({})",username);
       return userModel;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserModel userModel;
        try (Session c = DbUtil.getSession(this.model)) {
            userModel = c.executeWrite(tx -> {
            var query 
                = new Query(CustomUserStorageProviderConstants.QUERY_GET_USER_INFO_BY_EMAIL , 
                parameters(CustomUserStorageProviderConstants.DB_KEY_USER_EMAIL, email));
            var result = tx.run(query).list();
            if (result.size() == 1){
                return mapUser(realm, result.get(0));
            }
            return null;
          });
       }
       catch(Exception ex) {
           log.warn("Database error: unable to fetch record by user-email: ex={}", ex.getMessage());
           throw new RuntimeException("Database error: unable to fetch record by email",ex);
       }
       log.info("getUserByEmail({})",email);
       return userModel;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        log.info("supportsCredentialType({})",credentialType);
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.info("isConfiguredFor(realm={},user={},credentialType={})",realm.getName(), user.getUsername(), credentialType);
        // In our case, password is the only type of credential, so we allways return 'true' if
        // this is the credentialType
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        log.info("isValid(realm={},user={},credentialInput.type={})",realm.getName(), user.getUsername(), credentialInput.getType());
        if( !this.supportsCredentialType(credentialInput.getType())) {
            return false;
        }
        StorageId sid = new StorageId(user.getId());
        String username = sid.getExternalId();
       
        boolean isPasswordAuthentic = false;
        try (Session s = DbUtil.getSession(this.model)) {
            isPasswordAuthentic = s.executeWrite(tx -> {
                var query = new Query(CustomUserStorageProviderConstants.QUERY_GET_PASSWORD_FOR_USER , parameters(CustomUserStorageProviderConstants.DB_KEY_USER_NAME, username));
                var result = tx.run(query).list();
                if (result.size() == 1){
                    String password = result.get(0).get("password").asString();
                    return password.equals(credentialInput.getChallengeResponse());
                }
                return false;
            });
       }
       catch(Exception ex) {
           log.warn("Database error: unable to validate password: ex={}", ex.getMessage());
           throw new RuntimeException("Database error: unable to validate password",ex);
       }
       log.info("isValid({})",isPasswordAuthentic);
       return isPasswordAuthentic;
    }

    // UserQueryProvider implementation
    
    @Override
    public int getUsersCount(RealmModel realm) {
        int count = 0;
        try (Session c = DbUtil.getSession(this.model)) {
            count = c.executeWrite(tx -> {
            var query 
                = new Query(CustomUserStorageProviderConstants.QUERY_GET_USER_COUNT);
            var result = tx.run(query).list();
            if (result.size() == 1){
                return result.get(0).get(CustomUserStorageProviderConstants.DB_KEY_USER_COUNT).asInt();
            }
            return 0;
          });
        }
        catch(Exception ex) {
           log.warn("Database error: unable to get user count; ex={}", ex.getMessage());
           throw new RuntimeException("Database error: unable to get user count",ex);
        }
        log.info("getUsersCount: realm={}; count = {}", realm.getName(),count );
        return count;
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        log.info("getGroupMembersStream: realm={}", realm.getName());
        
        List<UserModel> users = new ArrayList<>();

    
        try (Session c = DbUtil.getSession(this.model)) {
            var txReturn = c.executeWrite(tx -> {
                int skipRecords = firstResult;
                if (firstResult > 0) {
                    skipRecords = firstResult - 1;
                };
                var query = new Query(CustomUserStorageProviderConstants.QUERY_GET_USER_STREAM_WITH_OFFSET_MAXRECORDS
                    , parameters(CustomUserStorageProviderConstants.RECORD_SKIP_KEY, skipRecords, CustomUserStorageProviderConstants.RECORD_LIMIT_KEY, maxResults));
                var result = tx.run(query);
                for (var user: result.list() )
                {
                    users.add(mapUser(realm,user));
                };
                return null;
          });
        }
        catch(Exception ex) {
           log.warn("Database error: unable to get user member stream; ex={}", ex.getMessage());
           throw new RuntimeException("Database error: unable to get user member stream",ex);
        }
        return users.stream();
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
        log.info("searchForUserStream: realm={}", realm.getName());

        List<UserModel> users = new ArrayList<>();

        try (Session c = DbUtil.getSession(this.model)) {
            var txReturn = c.executeWrite(tx -> {
                int skipRecords = firstResult;
                if (firstResult > 0) {
                    skipRecords = firstResult - 1;
                };
                String neo4jCompatibleSearchValue;
                if (search.equals(CustomUserStorageProviderConstants.WILDCARD)) {
                    neo4jCompatibleSearchValue = CustomUserStorageProviderConstants.EMPTY_STRING;
                } else {
                    neo4jCompatibleSearchValue = search;
                }
                log.info("user-record {} skip: {}, maxResults: {}", neo4jCompatibleSearchValue, skipRecords, maxResults);
                var query = new Query(CustomUserStorageProviderConstants.QUERY_SEARCH_USER_STREAM_WITH_OFFSET_MAXRECORDS
                    , parameters(CustomUserStorageProviderConstants.DB_KEY_USER_NAME, neo4jCompatibleSearchValue,CustomUserStorageProviderConstants.RECORD_SKIP_KEY,skipRecords, CustomUserStorageProviderConstants.RECORD_LIMIT_KEY, maxResults));
                var result = tx.run(query);
                for (var user: result.list() )
                {
                    log.info("retrieved user stream: {}", user);
                    users.add(mapUser(realm,user));
                };
                return null;
          });
        }
        catch(Exception ex) {
           log.warn("Database error: unable to get user member stream; ex={}", ex.getMessage());
           throw new RuntimeException("Database error: unable to get user member stream",ex);
        }
        return users.stream();
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return Stream.empty();
    }
    
    // Need To explore user attributes addition, roles and credentials
    @Override
    public UserModel addUser(RealmModel realm, String username) {
        try (Session s = DbUtil.getSession(this.model)) {
            var txReturn = s.executeWrite(tx -> {
                var query = new Query(CustomUserStorageProviderConstants.QUERY_CREATE_USER , parameters(CustomUserStorageProviderConstants.DB_KEY_USER_NAME, username));
                tx.run(query).list();
                return null;
            });
        }
        catch(Exception ex) {
           log.warn("Database error: unable to create user {};  ex={}", username, ex.getMessage());
           throw new RuntimeException("Database error: unable to create user",ex);
        }
        log.info("addUser: realm={}; user = {}", realm.getName(), username );
        CustomUser user = new CustomUser.Builder(ksession, realm, model,username).build();
        return user;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        String userName = user.getUsername();
        try (Session s = DbUtil.getSession(this.model)) {
            var txReturn = s.executeWrite(tx -> {
                var query = new Query(CustomUserStorageProviderConstants.QUERY_DELETE_USER , parameters(CustomUserStorageProviderConstants.DB_KEY_USER_NAME, userName));
                tx.run(query).list();
                return null;
            });
        }
        catch(Exception ex) {
           log.warn("Database error: unable to remove user {};  ex={}", userName, ex.getMessage());
           throw new RuntimeException("Database error: unable to remove user",ex);
        }
        log.info("removeUser: realm={}; user = {}", realm.getName(), userName );
        return true;
    }
    private UserModel mapUser(RealmModel realm, MapAccessor rs)  {
        
        DateFormat dateFormat = new SimpleDateFormat(CustomUserStorageProviderConstants.DB_KEY_BIRTH_DATE_FORMAT);
        Date date;
        try {
            date = dateFormat.parse(rs.get(CustomUserStorageProviderConstants.DB_KEY_USER_BIRTHDATE).asString());
        } catch (ParseException e) {
           return null;
        }
        CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.get(CustomUserStorageProviderConstants.DB_KEY_USER_NAME).asString())
          .email(rs.get(CustomUserStorageProviderConstants.DB_KEY_USER_EMAIL).asString())
          .firstName(rs.get(CustomUserStorageProviderConstants.DB_KEY_USER_FIRST_NAME).asString())
          .lastName(rs.get(CustomUserStorageProviderConstants.DB_KEY_USER_LAST_NAME).asString())
          .birthDate(date)
          .build();
        
        return user;
    }

}
