package yspay.qrcode.common.filter.dubbo;

import com.alibaba.dubbo.common.Constants;
import com.alibaba.dubbo.common.URL;
import com.alibaba.dubbo.common.extension.Activate;
import com.alibaba.dubbo.rpc.*;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.alibaba.fastjson.serializer.ValueFilter;
import kalvan.log.logback.layout.converter.LogPreFixConverter;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.MessageFormat;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Activate(group = { Constants.PROVIDER,Constants.CONSUMER })
public class AccessLogExtFilter implements Filter {
    private static final String ACCESS_LOG_KEY = "dubbo.accesslog";
    private static final String ACCESS_LOG_ASYNC_KEY = "dubbo.accesslog.async";
    private static final Logger logger = LoggerFactory.getLogger("dubbo.accesslog");
    private static final Logger logger_async = LoggerFactory.getLogger("dubbo.accesslog.async");
    private static final String TRACE_NO = "YSPAY_TRACE_NO";
    private static final String CONSUMER = "consumer";
    private static final String PROVIDER = "provider";
    private static final String VER = "1.1.6";
    private static final long WARN_SERIALIZE_TIME = 3000L;
    private static final int LOG_ASYN_LENGTH_LIMIT = 10000;
    private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
    private static final String[] METHOD_NO_LOG = new String[]{"encrypt", "decrypt"};
    private static final Set<String> SENSITIVE_KEY = new HashSet();
    private static final ValueFilter profilter;

    public AccessLogExtFilter() {
    }

    public Result invoke(Invoker<?> invoker, Invocation inv) throws RpcException {
        StringBuilder sn = new StringBuilder();
        RpcContext context = RpcContext.getContext();
        String side = context.isConsumerSide() ? "consumer" : "provider";
        boolean isSensitiveMethod = this.handleMethodSensitive(inv);

        try {
            this.handleTraceNo();
            sn.append(this.handleBeginInvokeInfo(invoker, inv, side));
            sn.append(this.handleBeginInvokeParams(inv, isSensitiveMethod));
        } catch (Throwable var57) {
            logger.info("Exception in RpcFilter of service(" + invoker + " -> " + inv + ")", var57);
        } finally {
            logger.info(sn.toString());
        }

        long begin = System.currentTimeMillis();
        boolean hasException = false;
        String exceptionMsg = null;
        Object resultValue = null;
        boolean var44 = false;

        Result var13;
        try {
            var44 = true;
            Result result = invoker.invoke(inv);

            try {
                resultValue = result.getValue();
                hasException = result.hasException();
                if (hasException && result.getException() != null) {
                    exceptionMsg = result.getException().getMessage();
                }
            } catch (Throwable var54) {
                logger.info("Exception in handleResult RpcFilter of service(" + invoker + " -> " + inv + ")", var54);
            }

            var13 = result;
            var44 = false;
        } catch (Throwable var55) {
            hasException = true;
            exceptionMsg = var55.getMessage();
            throw var55;
        } finally {
            if (var44) {
                try {
                    long end = System.currentTimeMillis();
                    long costTime = end - begin;
                    StringBuilder sb = new StringBuilder();
                    sb.append(" finish dubbo invoke(" + side + ") - ");
                    sb.append(this.commonMsg(invoker, inv));
                    String invokeResult = this.handleInvokeResultParams(isSensitiveMethod, resultValue);
                    if (this.needLogAsyn(invokeResult)) {
                        sb.append(",result=[" + invokeResult.substring(0, 10000) + "...(响应结果过长[" + invokeResult.length() + "]，完整内容异步输出)],costTime=" + costTime + "ms,localHost=(" + context.getLocalHostName() + ")" + context.getLocalHost() + ":" + context.getLocalPort() + ",ver=" + "1.1.6" + ",hasException=" + hasException + ",exceptionMsg=" + exceptionMsg);
                        logger.info(sb.toString());
                        this.logAsyn(this.commonMsg(invoker, inv) + " 完整响应参数：" + invokeResult);
                    } else {
                        sb.append(",result=[" + invokeResult + "],costTime=" + costTime + "ms,localHost=(" + context.getLocalHostName() + ")" + context.getLocalHost() + ":" + context.getLocalPort() + ",ver=" + "1.1.6" + ",hasException=" + hasException + ",exceptionMsg=" + exceptionMsg);
                        logger.info(sb.toString());
                    }

                    if ("provider".equals(side)) {
                        RpcStatus status = RpcStatus.getStatus(invoker.getUrl(), inv.getMethodName());
                        URL url = invoker.getUrl();
                        String methodName = inv.getMethodName();
                        int max = url.getMethodParameter(methodName, "executes", 0);
                        if (max <= 0) {
                            max = url.getMethodParameter(methodName, "default.executes", 0);
                        }

                        int left = max - status.getActive();
                        if (left < 50) {
                            logger.warn("dubbo status:[method:{},status:{},max:{},left:{}]", new Object[]{methodName, JSONObject.toJSONString(status), max, left});
                        }
                    }
                } catch (Throwable var52) {
                    logger.info("Exception in handleResult RpcFilter of service(" + invoker + " -> " + inv + ")", var52);
                }

            }
        }

        try {
            long end = System.currentTimeMillis();
            long costTime = end - begin;
            StringBuilder sb = new StringBuilder();
            sb.append(" finish dubbo invoke(" + side + ") - ");
            sb.append(this.commonMsg(invoker, inv));
            String invokeResult = this.handleInvokeResultParams(isSensitiveMethod, resultValue);
            if (this.needLogAsyn(invokeResult)) {
                sb.append(",result=[" + invokeResult.substring(0, 10000) + "...(响应结果过长[" + invokeResult.length() + "]，完整内容异步输出)],costTime=" + costTime + "ms,localHost=(" + context.getLocalHostName() + ")" + context.getLocalHost() + ":" + context.getLocalPort() + ",ver=" + "1.1.6" + ",hasException=" + hasException + ",exceptionMsg=" + exceptionMsg);
                logger.info(sb.toString());
                this.logAsyn(this.commonMsg(invoker, inv) + " 完整响应参数：" + invokeResult);
            } else {
                sb.append(",result=[" + invokeResult + "],costTime=" + costTime + "ms,localHost=(" + context.getLocalHostName() + ")" + context.getLocalHost() + ":" + context.getLocalPort() + ",ver=" + "1.1.6" + ",hasException=" + hasException + ",exceptionMsg=" + exceptionMsg);
                logger.info(sb.toString());
            }

            if ("provider".equals(side)) {
                RpcStatus status = RpcStatus.getStatus(invoker.getUrl(), inv.getMethodName());
                URL url = invoker.getUrl();
                String methodName = inv.getMethodName();
                int max = url.getMethodParameter(methodName, "executes", 0);
                if (max <= 0) {
                    max = url.getMethodParameter(methodName, "default.executes", 0);
                }

                int left = max - status.getActive();
                if (left < 50) {
                    logger.warn("dubbo status:[method:{},status:{},max:{},left:{}]", new Object[]{methodName, JSONObject.toJSONString(status), max, left});
                }
            }
        } catch (Throwable var53) {
            logger.info("Exception in handleResult RpcFilter of service(" + invoker + " -> " + inv + ")", var53);
        }

        return var13;
    }

    private void logAsyn(String log) {
        logger_async.info(log);
    }

    private boolean needLogAsyn(String invokeResult) {
        return invokeResult != null && invokeResult.length() > 10000;
    }

    private String handleInvokeResultParams(boolean isSensitiveMethod, Object resultValue) {
        long begin = System.currentTimeMillis();
        String result = isSensitiveMethod ? " ****** " : JSONObject.toJSONString(resultValue, profilter, new SerializerFeature[]{SerializerFeature.WriteMapNullValue, SerializerFeature.SortField});
        long cost = System.currentTimeMillis() - begin;
        if (cost > 3000L) {
            logger.warn("序列化耗时过长：" + cost);
        }

        return result;
    }

    private String handleBeginInvokeParams(Invocation inv, boolean isSensitiveMethod) {
        StringBuilder sn = new StringBuilder();
        Object[] args = inv.getArguments();
        if (args != null && args.length > 0) {
            if (isSensitiveMethod) {
                sn.append(" ****** ");
            } else {
                sn.append(JSONObject.toJSONString(args, profilter, new SerializerFeature[]{SerializerFeature.WriteMapNullValue, SerializerFeature.SortField}));
            }
        }

        return sn.toString();
    }

    private String handleBeginInvokeInfo(Invoker<?> invoker, Invocation inv, String side) {
        StringBuilder sn = new StringBuilder();
        sn.append(MessageFormat.format(" begin dubbo invoke({0}) - ", side));
        sn.append(this.commonMsg(invoker, inv));
        sn.append("(");
        Class<?>[] types = inv.getParameterTypes();
        if (types != null && types.length > 0) {
            boolean first = true;
            Class[] arr$ = types;
            int len$ = types.length;

            for(int i$ = 0; i$ < len$; ++i$) {
                Class<?> type = arr$[i$];
                if (first) {
                    first = false;
                } else {
                    sn.append(",");
                }

                sn.append(type.getName());
            }
        }

        sn.append(") ");
        return sn.toString();
    }

    private boolean handleMethodSensitive(Invocation inv) {
        boolean result = false;

        try {
            String methodName = inv.getMethodName().toLowerCase();
            String[] arr$ = METHOD_NO_LOG;
            int len$ = arr$.length;

            for(int i$ = 0; i$ < len$; ++i$) {
                String str = arr$[i$];
                if (methodName.contains(str)) {
                    result = true;
                    break;
                }
            }
        } catch (Throwable var8) {
            logger.warn("判断方法是否需要加密异常", var8);
            result = true;
        }

        return result;
    }

    private void handleTraceNo() {
        boolean isConsumer = RpcContext.getContext().isConsumerSide();
        if (isConsumer) {
            RpcContext.getContext().setAttachment("YSPAY_TRACE_NO", LogPreFixConverter.getCurrentThreadLogPreFix(""));
        } else {
            String traceNo = RpcContext.getContext().getAttachment("YSPAY_TRACE_NO");
            if (StringUtils.isBlank(traceNo)) {
                traceNo = UUID.randomUUID().toString();
            }

            LogPreFixConverter.setLogPreFixNoAppendThread(traceNo);
        }

    }

    private String commonMsg(Invoker<?> invoker, Invocation inv) {
        RpcContext context = RpcContext.getContext();
        String serviceName = invoker.getInterface().getName();
        String version = invoker.getUrl().getParameter("version");
        String group = invoker.getUrl().getParameter("group");
        StringBuilder sn = new StringBuilder();
        sn.append(context.getRemoteHost()).append(":").append(context.getRemotePort()).append(" - ");
        if (null != group && group.length() > 0) {
            sn.append(group).append("/");
        }

        sn.append(serviceName);
        if (null != version && version.length() > 0) {
            sn.append(":").append(version);
        }

        sn.append(" ");
        sn.append(inv.getMethodName());
        return sn.toString();
    }

    static {
        SENSITIVE_KEY.add("serialversionuid");
        SENSITIVE_KEY.add("accountNo");
        SENSITIVE_KEY.add("card_no");
        SENSITIVE_KEY.add("accNo");
        SENSITIVE_KEY.add("cvv");
        SENSITIVE_KEY.add("effdate");
        SENSITIVE_KEY.add("expdate");
        SENSITIVE_KEY.add("validdate");
        SENSITIVE_KEY.add("name");
        SENSITIVE_KEY.add("bankName");
        SENSITIVE_KEY.add("bankaccountName");
        SENSITIVE_KEY.add("accountName");
        SENSITIVE_KEY.add("custname");
        SENSITIVE_KEY.add("username");
        SENSITIVE_KEY.add("certifitype");
        SENSITIVE_KEY.add("certify");
        SENSITIVE_KEY.add("certifino");
        SENSITIVE_KEY.add("certificateNo");
        SENSITIVE_KEY.add("certifyno");
        SENSITIVE_KEY.add("legalRepCertifyNum");
        SENSITIVE_KEY.add("id_no");
        SENSITIVE_KEY.add("mobile");
        SENSITIVE_KEY.add("mobNo");
        SENSITIVE_KEY.add("phone");
        SENSITIVE_KEY.add("phoneNum");
        SENSITIVE_KEY.add("tel");
        SENSITIVE_KEY.add("address");
        SENSITIVE_KEY.add("addr");
        SENSITIVE_KEY.add("email");
        SENSITIVE_KEY.add("bank_account_no");
        SENSITIVE_KEY.add("telephone_no");
        SENSITIVE_KEY.add("cert_expire");
        SENSITIVE_KEY.add("telephone");
        profilter = new ValueFilter() {
            public Object process(Object object, String name, Object value) {
                return AccessLogExtFilter.SENSITIVE_KEY.contains(name) ? "***" : value;
            }
        };
    }
}
