package demo;

import org.springframework.http.*;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;

/**
 * @author Zero
 *         Created on 2016/9/6.
 */
@Controller
@RequestMapping("/")
public class MockClientController {

    RestTemplate restTemplate = new RestTemplate();

    //第一步:获取授权码,客户端引导用户到资源服务器登录(比如点击'QQ登录'按钮)
    //http://localhost:8080/uaa/oauth/authorize?client_id=acme&response_type=code&state=teststate&redirect_uri=http://localhost:8080/uaa/authorize_callback

    //第二步:用户登录到资源服务器.
    //输入用户名密码等

    //第三步:确认授权
    //登录成功后确认授权,授权就会跳转的redirect_uri,并传入参数code和state(state由第一步决定)

    //第四步:获取token,客户端通过资源服务器的回调获取token
    @RequestMapping(value = "/authorize_callback", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getToken(String code, String state, HttpServletRequest request) {
        //授权码是一次性用品
        System.out.println("======授权码=============");
        System.out.println(code);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.set("grant_type", "authorization_code");
        form.set("client_id", "acme");
        form.set("client_secret", "acmesecret");
        form.set("code", code);
        form.set("redirect_uri", "http://localhost:8080/uaa/authorize_callback");//这个地址和获取授权码时提供的地址一致

        HttpHeaders headers = new HttpHeaders();

        RequestEntity<MultiValueMap<String, String>> req
                = new RequestEntity<>(form, headers, HttpMethod.POST, URI.create("http://localhost:8080/uaa/oauth/token"));
        ResponseEntity<DefaultOAuth2AccessToken> responseEntity = restTemplate.exchange(req, DefaultOAuth2AccessToken.class);

        return ResponseEntity.ok(responseEntity.getBody());

    }


}
