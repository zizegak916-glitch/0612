import com.fool.ipbatch.SubscriptionDownloader;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public final class DownloaderSmokeTest {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] subscription = "ss://test@example.invalid:443#local-test".getBytes(StandardCharsets.UTF_8);
        server.createContext("/sub", new HttpHandler() {
            @Override public void handle(HttpExchange exchange) {
                try {
                    exchange.sendResponseHeaders(200, subscription.length);
                    exchange.getResponseBody().write(subscription);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    exchange.close();
                }
            }
        });
        server.createContext("/jump", new HttpHandler() {
            @Override public void handle(HttpExchange exchange) {
                try {
                    exchange.getResponseHeaders().add("Location", "/sub");
                    exchange.sendResponseHeaders(302, -1);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    exchange.close();
                }
            }
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            SubscriptionDownloader downloader = new SubscriptionDownloader();
            expectFailure(downloader, "http://127.0.0.1:" + port + "/sub", false, "勾选允许访问私网订阅");
            expectFailure(downloader, "http://8.8.8.8/sub", true, "公网订阅必须使用 HTTPS");
            SubscriptionDownloader.Download direct = downloader.download(
                    "http://127.0.0.1:" + port + "/sub", "test", 2000, true);
            check(direct.content.equals(new String(subscription, StandardCharsets.UTF_8)), "本机 HTTP 内容不一致");
            SubscriptionDownloader.Download redirected = downloader.download(
                    "http://127.0.0.1:" + port + "/jump", "test", 2000, true);
            check(redirected.redirects == 1, "本机跳转计数不正确");
            System.out.println("DownloaderSmokeTest OK");
        } finally {
            server.stop(0);
        }
    }

    private static void expectFailure(SubscriptionDownloader downloader, String url,
                                      boolean allowPrivate, String expected) throws Exception {
        try {
            downloader.download(url, "test", 1000, allowPrivate);
            throw new AssertionError("预期拒绝但请求成功：" + url);
        } catch (Exception e) {
            check(e.getMessage() != null && e.getMessage().contains(expected),
                    "拒绝原因不正确：" + e.getMessage());
        }
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
