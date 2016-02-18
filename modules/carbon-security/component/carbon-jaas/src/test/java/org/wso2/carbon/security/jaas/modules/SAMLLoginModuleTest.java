package org.wso2.carbon.security.jaas.modules;

import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.security.jaas.CarbonCallbackHandler;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;


/**
 * Created by yasiru on 2/15/16.
 */
public class SAMLLoginModuleTest {
    private class SAMLConfig extends Configuration {
        private String b64CertFile;

        public SAMLConfig(String b64CertFile) {
            this.b64CertFile = b64CertFile;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            byte[] b64ByteCertFile = b64CertFile.getBytes(StandardCharsets.UTF_8);

            Base64.Decoder decoder = Base64.getDecoder();
            Certificate x509Certificate = null;
            KeyStore keystore = null;
            try {
                keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(null, "wso2carbon".toCharArray());
                x509Certificate = CertificateFactory.getInstance("x509").generateCertificate(new ByteArrayInputStream(b64ByteCertFile));
                keystore.setCertificateEntry("wso2carbon", x509Certificate);
            } catch (Exception e) {
                Assert.assertTrue(false);
            }
            HashMap<String, Object> options = new HashMap<>();
            options.put(SAMLLoginModule.OPT_KEYSTORE_INSTANCE, keystore);

            AppConfigurationEntry[] configurationEntries = new AppConfigurationEntry[1];
            configurationEntries[0] = new AppConfigurationEntry(SAMLLoginModule.class.getName(),
                    AppConfigurationEntry.LoginModuleControlFlag
                            .REQUIRED, options);
            return configurationEntries;
        }
    }
    private final String VALID_B64_CERT_FILE = "-----BEGIN CERTIFICATE-----\n" +
            "MIICNTCCAZ6gAwIBAgIES343gjANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJV\n" +
            "UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxDTALBgNVBAoM\n" +
            "BFdTTzIxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xMDAyMTkwNzAyMjZaFw0zNTAy\n" +
            "MTMwNzAyMjZaMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwN\n" +
            "TW91bnRhaW4gVmlldzENMAsGA1UECgwEV1NPMjESMBAGA1UEAwwJbG9jYWxob3N0\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUp/oV1vWc8/TkQSiAvTousMzO\n" +
            "M4asB2iltr2QKozni5aVFu818MpOLZIr8LMnTzWllJvvaA5RAAdpbECb+48FjbBe\n" +
            "0hseUdN5HpwvnH/DW8ZccGvk53I6Orq7hLCv1ZHtuOCokghz/ATrhyPq+QktMfXn\n" +
            "RS4HrKGJTzxaCcU7OQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcN\n" +
            "AQEFBQADgYEAW5wPR7cr1LAdq+IrR44iQlRG5ITCZXY9hI0PygLP2rHANh+PYfTm\n" +
            "xbuOnykNGyhM6FjFLbW2uZHQTY1jMrPprjOrmyK5sjJRO4d1DeGHT/YnIjs9JogR\n" +
            "Kv4XHECwLtIVdAbIdWHEtVZJyMSktcyysFcvuhPQK8Qc/E/Wq8uHSCo=\n" +
            "-----END CERTIFICATE-----\n";
    private final String INVALID_B64_CERT_FILE = "-----BEGIN CERTIFICATE-----\n" +
            "MIICQjCCAasCBElBAsYwDQYJKoZIhvcNAQEEBQAwZzELMAkGA1UEBhMCTEsxDTAL\n" +
            "BgNVBAoTBFdTTzIxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0\n" +
            "bGUxDTALBgNVBAsTBE5vbmUxEzARBgNVBAMTCndzbzJjYXJib24wIBcNMDgxMjEx\n" +
            "MTIwODM4WhgPMjI4MjA5MjUxMjA4MzhaMGcxCzAJBgNVBAYTAkxLMQ0wCwYDVQQK\n" +
            "EwRXU08yMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMQ0w\n" +
            "CwYDVQQLEwROb25lMRMwEQYDVQQDEwp3c28yY2FyYm9uMIGfMA0GCSqGSIb3DQEB\n" +
            "AQUAA4GNADCBiQKBgQCnDt65/AhKuuJ+9Zy7cRJt64C2eqAN5tSSf1Idh2Jz0pRI\n" +
            "Wpkd3V2gfpWg9fhY5uNFC3+aIMrUZVEzMqGDBv1Zym4jXMv4tsf4IGvVMuHgV4PS\n" +
            "DoN3QD0qAxRCEZNMCMJaOoVtq0SyTvJ2mvOHoZge2XWJtNDV2OuYvRb40YvrNwID\n" +
            "AQABMA0GCSqGSIb3DQEBBAUAA4GBAAiruslhFOMzFYgiVzxrgQZo405C2EHTozCA\n" +
            "CgtJ9ElMuyiWnai/sRViVAY3dkV7gilOYl8zXBSVlpagtB/NiibY+zPv6lXKWSBu\n" +
            "oFwCsKeEDjriwEvLT9Gxi2gEHth4lm6E/FE14JDjSk9Urn7+HTpPQHDkHSo05Y0R\n" +
            "3irtIjyx\n" +
            "-----END CERTIFICATE-----";
    private final String B64_SAML_RESPONSE = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWwycDpSZXNwb25zZSBEZXN0aW5hdGlvbj0iaHR0cDovL2xvY2FsaG9zdDoyNDI0L3RyYXZlbG9jaXR5LmNvbS9ob21lLmpzcCIgSUQ9Im5kbmpsYmlua2VqZ29naGNkaGpwamtwcG1lb2NvaWZjZ2xvZ2NtZ2kiIEluUmVzcG9uc2VUbz0iZm9hYmdlcG1mb2lwb2lpbW9sbG1vaWhjbmVrbW5sbGFnaG9jY2ZkbCIgSXNzdWVJbnN0YW50PSIyMDE2LTAyLTExVDEzOjQ5OjQyLjk5M1oiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzYW1sMjpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5sb2NhbGhvc3Q8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48ZHM6UmVmZXJlbmNlIFVSST0iI25kbmpsYmlua2VqZ29naGNkaGpwamtwcG1lb2NvaWZjZ2xvZ2NtZ2kiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM%2BPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8%2BPGRzOkRpZ2VzdFZhbHVlPnhnY2NSRVkzV0dyZGdGSlc4ektlSXZQb0wrdz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU%2BU3dpWWRBbnFSQUV0bnZTbzZFVGkzTG9qUkNuNXF5Y2xEMDdoaUlNKzhvU2hBakxGWDI2aFNsaXhybUJUVlVYVUxsKzl6OUNpeWdub0N4VWxCb0ZhSU04bjBBR3dMdTM0dWx1Z0dKeDkrb3JMRE1qVU5OR0t4ekNXZk9aOTJMcEN2MkJFajR3SDFnWm0zQlpPbUVOMDl0Z3dmVHZmckpXS1R5M0NkWVR6ZFlBPTwvZHM6U2lnbmF0dXJlVmFsdWU%2BPGRzOktleUluZm8%2BPGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU%2BTUlJQ05UQ0NBWjZnQXdJQkFnSUVTMzQzZ2pBTkJna3Foa2lHOXcwQkFRVUZBREJWTVFzd0NRWURWUVFHRXdKVlV6RUxNQWtHQTFVRUNBd0NRMEV4RmpBVUJnTlZCQWNNRFUxdmRXNTBZV2x1SUZacFpYY3hEVEFMQmdOVkJBb01CRmRUVHpJeEVqQVFCZ05WQkFNTUNXeHZZMkZzYUc5emREQWVGdzB4TURBeU1Ua3dOekF5TWpaYUZ3MHpOVEF5TVRNd056QXlNalphTUZVeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlEQUpEUVRFV01CUUdBMVVFQnd3TlRXOTFiblJoYVc0Z1ZtbGxkekVOTUFzR0ExVUVDZ3dFVjFOUE1qRVNNQkFHQTFVRUF3d0piRzlqWVd4b2IzTjBNSUdmTUEwR0NTcUdTSWIzRFFFQkFRVUFBNEdOQURDQmlRS0JnUUNVcC9vVjF2V2M4L1RrUVNpQXZUb3VzTXpPTTRhc0IyaWx0cjJRS296bmk1YVZGdTgxOE1wT0xaSXI4TE1uVHpXbGxKdnZhQTVSQUFkcGJFQ2IrNDhGamJCZTBoc2VVZE41SHB3dm5IL0RXOFpjY0d2azUzSTZPcnE3aExDdjFaSHR1T0Nva2doei9BVHJoeVBxK1FrdE1mWG5SUzRIcktHSlR6eGFDY1U3T1FJREFRQUJveEl3RURBT0JnTlZIUThCQWY4RUJBTUNCUEF3RFFZSktvWklodmNOQVFFRkJRQURnWUVBVzV3UFI3Y3IxTEFkcStJclI0NGlRbFJHNUlUQ1pYWTloSTBQeWdMUDJySEFOaCtQWWZUbXhidU9ueWtOR3loTTZGakZMYlcydVpIUVRZMWpNclBwcmpPcm15SzVzakpSTzRkMURlR0hUL1luSWpzOUpvZ1JLdjRYSEVDd0x0SVZkQWJJZFdIRXRWWkp5TVNrdGN5eXNGY3Z1aFBRSzhRYy9FL1dxOHVIU0NvPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE%2BPC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sMnA6U3RhdHVzPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8%2BPC9zYW1sMnA6U3RhdHVzPjxzYW1sMjpBc3NlcnRpb24gSUQ9ImhsbG9wZ2ZlZ2dua3BhbW5tYmRjaWZpamRlYm5nb3BsZ2dmYmxvZmciIElzc3VlSW5zdGFudD0iMjAxNi0wMi0xMVQxMzo0OTo0Mi45OTVaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5sb2NhbGhvc3Q8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48ZHM6UmVmZXJlbmNlIFVSST0iI2hsbG9wZ2ZlZ2dua3BhbW5tYmRjaWZpamRlYm5nb3BsZ2dmYmxvZmciPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM%2BPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8%2BPGRzOkRpZ2VzdFZhbHVlPmxwRzZrY2VGTlpvNWN1RHo3Tk93NTd1VW9XYz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU%2BV2ZSdjZhb0h3R0s5YUthdndJbUdiL3BkUTRjUzNVRUdLUEF6ZE9uUll3bkJuQVpJQTVVT293d0QzaGUwelprMnZlY1lTdE1oRzkrdFFrUmpxK09ZN3FpRTRFcDFGWExYTmdxYVFYYWxFdG9idlQwVk9SeGkyaHNnS2xPUXBsc2F0WFcvaEJsekEvdEIwZlNrbHFZV01KOHljR2FhNVRTYitwWTRFc2dXR3JvPTwvZHM6U2lnbmF0dXJlVmFsdWU%2BPGRzOktleUluZm8%2BPGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU%2BTUlJQ05UQ0NBWjZnQXdJQkFnSUVTMzQzZ2pBTkJna3Foa2lHOXcwQkFRVUZBREJWTVFzd0NRWURWUVFHRXdKVlV6RUxNQWtHQTFVRUNBd0NRMEV4RmpBVUJnTlZCQWNNRFUxdmRXNTBZV2x1SUZacFpYY3hEVEFMQmdOVkJBb01CRmRUVHpJeEVqQVFCZ05WQkFNTUNXeHZZMkZzYUc5emREQWVGdzB4TURBeU1Ua3dOekF5TWpaYUZ3MHpOVEF5TVRNd056QXlNalphTUZVeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlEQUpEUVRFV01CUUdBMVVFQnd3TlRXOTFiblJoYVc0Z1ZtbGxkekVOTUFzR0ExVUVDZ3dFVjFOUE1qRVNNQkFHQTFVRUF3d0piRzlqWVd4b2IzTjBNSUdmTUEwR0NTcUdTSWIzRFFFQkFRVUFBNEdOQURDQmlRS0JnUUNVcC9vVjF2V2M4L1RrUVNpQXZUb3VzTXpPTTRhc0IyaWx0cjJRS296bmk1YVZGdTgxOE1wT0xaSXI4TE1uVHpXbGxKdnZhQTVSQUFkcGJFQ2IrNDhGamJCZTBoc2VVZE41SHB3dm5IL0RXOFpjY0d2azUzSTZPcnE3aExDdjFaSHR1T0Nva2doei9BVHJoeVBxK1FrdE1mWG5SUzRIcktHSlR6eGFDY1U3T1FJREFRQUJveEl3RURBT0JnTlZIUThCQWY4RUJBTUNCUEF3RFFZSktvWklodmNOQVFFRkJRQURnWUVBVzV3UFI3Y3IxTEFkcStJclI0NGlRbFJHNUlUQ1pYWTloSTBQeWdMUDJySEFOaCtQWWZUbXhidU9ueWtOR3loTTZGakZMYlcydVpIUVRZMWpNclBwcmpPcm15SzVzakpSTzRkMURlR0hUL1luSWpzOUpvZ1JLdjRYSEVDd0x0SVZkQWJJZFdIRXRWWkp5TVNrdGN5eXNGY3Z1aFBRSzhRYy9FL1dxOHVIU0NvPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE%2BPC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDplbWFpbEFkZHJlc3MiPmFkbWluQGNhcmJvbi5zdXBlcjwvc2FtbDI6TmFtZUlEPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI%2BPHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iZm9hYmdlcG1mb2lwb2lpbW9sbG1vaWhjbmVrbW5sbGFnaG9jY2ZkbCIgTm90T25PckFmdGVyPSIyMDE2LTAyLTExVDEzOjU0OjQyLjk5M1oiIFJlY2lwaWVudD0iaHR0cDovL2xvY2FsaG9zdDoyNDI0L3RyYXZlbG9jaXR5LmNvbS9ob21lLmpzcCIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q%2BPHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE2LTAyLTExVDEzOjQ5OjQyLjk5NVoiIE5vdE9uT3JBZnRlcj0iMjAxNi0wMi0xMVQxMzo1NDo0Mi45OTNaIj48c2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDI6QXVkaWVuY2U%2BdHJhdmVsb2NpdHkuY29tPC9zYW1sMjpBdWRpZW5jZT48L3NhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24%2BPC9zYW1sMjpDb25kaXRpb25zPjxzYW1sMjpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTYtMDItMTFUMTM6NDk6NDMuMDAzWiIgU2Vzc2lvbkluZGV4PSI4YzFmOGRlYS0wM2Y3LTRlNWItYTM5NC03ZDY1Y2E5NDIyMjEiPjxzYW1sMjpBdXRobkNvbnRleHQ%2BPHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg%3D%3D";

    @Test
    public void testSAMLSuccessFullLogin() {
        HttpRequest httpRequest = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "");
        httpRequest.setUri("http://localhost:8080/?SAMLResponse=" + B64_SAML_RESPONSE);
        CallbackHandler callbackHandler = new CarbonCallbackHandler(httpRequest);

        LoginContext loginContext;

        try {
            loginContext = new LoginContext("CarbonSecurityConfig", new Subject(), callbackHandler, new SAMLConfig(VALID_B64_CERT_FILE));
            loginContext.login();
            Assert.assertTrue(true);

        } catch (LoginException e) {
            Assert.assertTrue(false);
        }

    }
    @Test
    public void testSAMLWrongCertLogin() {
        HttpRequest httpRequest = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "");
        httpRequest.setUri("http://localhost:8080/?SAMLResponse=" + B64_SAML_RESPONSE);
        CallbackHandler callbackHandler = new CarbonCallbackHandler(httpRequest);

        LoginContext loginContext;

        try {
            loginContext = new LoginContext("CarbonSecurityConfig", new Subject(), callbackHandler, new SAMLConfig(INVALID_B64_CERT_FILE));
            loginContext.login();
            //getting a successful login would be an error
            Assert.assertTrue(false);

        } catch (LoginException e) {
            //signature verification has failed, user not logged in.
            Assert.assertTrue(true);
        }
    }
}