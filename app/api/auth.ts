import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import { ACCESS_CODE_PREFIX } from "../constant";
import { OPENAI_URL } from "./common";
import * as jose from "jose";

function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isOpenAiKey = !token.startsWith(ACCESS_CODE_PREFIX);

  return {
    accessCode: isOpenAiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    apiKey: isOpenAiKey ? token : "",
  };
}

export async function auth(req: NextRequest, skipCustomKey = true) {
  const authToken =
    req.headers.get("Authorization") ??
    req.nextUrl.searchParams.get("Authorization") ??
    "";

  // check if it is openai api key or user token
  const { accessCode, apiKey: token } = parseApiKey(authToken);

  const hashedCode = md5.hash(accessCode ?? "").trim();

  const serverConfig = getServerSideConfig();
  console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  console.log("[Auth] got access code:", accessCode);
  console.log("[Auth] hashed access code:", hashedCode);
  console.log("[User IP] ", getIP(req));
  console.log("[Time] ", new Date().toLocaleString());

  if (serverConfig.needCode && !serverConfig.codes.has(hashedCode)) {
    if (!token || !skipCustomKey) {
      return {
        error: true,
        msg: !accessCode ? "empty access code" : "wrong access code",
      };
    }
  }
  // only allow access code
  if (token === "") {
    return {
      error: true,
      msg: "需要登录",
    };
  }

  const JWKS = jose.createRemoteJWKSet(
    new URL("http://127.0.0.1:8001/oauth2/certs"),
  );
  try {
    const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS);
    console.log(protectedHeader);
    console.log(payload);
  } catch (e) {
    console.log("[Auth] err " + e + " at" + token);
    return {
      error: true,
      msg: "请尝试刷新页面",
    };
  }

  const apiKey = serverConfig.apiKey;
  if (apiKey) {
    console.log("[Auth] use system api key");
    req.headers.set("Authorization", `Bearer ${apiKey}`);
  } else {
    console.log("[Auth] admin did not provide an api key");
  }

  return {
    error: false,
  };
}
