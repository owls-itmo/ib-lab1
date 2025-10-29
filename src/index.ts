import express from "express";
import sqlite from "sqlite3";
import * as jose from "jose";

import { HashedPassword, UserModel } from "./user.model.js";

const alg = "HS512";
const JWT_SECRET = await jose.generateSecret(alg);
const MIN_PASSWORD_LENGTH = 3;

const { Database } = sqlite;

const db = new Database("users.db");
const app = express();

interface LoginData {
  login: string;
  password: string;
}

await new Promise((res, rej) => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
  login text NOT NULL UNIQUE,
  password_hash text NOT NULL
);`,
    (err) => {
      if (err) {
        rej(`Could not create users table! Error: ${err}`);
      } else {
        res(undefined);
      }
    }
  );
});

const SQL_GET_ALL_USERS = db.prepare(`SELECT login FROM users;`);

const SQL_GET_USER = db.prepare(
  "SELECT login, password_hash FROM users WHERE login = ?;"
);

const SQL_ADD_USER = db.prepare(
  `INSERT OR ABORT INTO users (login, password_hash) VALUES ($login, $password_hash);`
);

app.use(express.json());

app.get("/api/data", guardEndpoint, async (req, resp, next) => {
  const login = (req as any).login;
  const user = await getUser(login);
  const logins: string[] = await new Promise((res, rej) => {
    SQL_GET_ALL_USERS.all((err, rows) => {
      if (err) {
        return rej(err);
      }

      return res(rows.map((row) => (row as { login: string }).login));
    });
  });

  resp.send({
    requester: user.login,
    all_users: logins,
  });
});

app.post("/auth/login", validateLoginData, async (req, resp, next) => {
  try {
    const login_data = req.body as LoginData;

    // get the user from database
    const user = await getUser(login_data.login);

    // validate password with data fetched from database
    if (!user.password_hash.is_password_valid(login_data.password)) {
      resp.status(401);
      resp.send("Invalid password!");
      return;
    }

    resp.status(200);
    const jwt = await new jose.SignJWT({
      login: user.login,
    })
      .setAudience("localhost")
      .setExpirationTime("30m")
      .setIssuer("me")
      .setIssuedAt()
      .setProtectedHeader({ alg })
      .sign(JWT_SECRET);

    resp.send({ token: jwt });
  } catch (error) {
    next(error);
  }
});

app.post("/auth/register", validateLoginData, async (req, resp, next) => {
  const login_data = req.body as LoginData;
  const user = new UserModel(login_data.login, login_data.password);
  await new Promise((res, rej) =>
    SQL_ADD_USER.run(
      {
        $login: user.login,
        $password_hash: user.password_hash.value,
      },
      (err) => {
        if (err) {
          return rej(err);
        }

        return res(undefined);
      }
    )
  );

  resp.send();
});

app.listen(8080);

function validateLoginData(
  req: express.Request,
  resp: express.Response,
  next: express.NextFunction
) {
  const body = req.body as Partial<LoginData> | undefined;
  if (body == undefined) {
    resp.status(422);
    resp.send(
      "Request body is empty. Should be valid json with login and password"
    );
    return;
  }

  if (body.login == null) {
    resp.status(422);
    resp.send('Request body does not have "login" field!');
    return;
  }

  if (body.login.length < 1) {
    resp.status(422);
    resp.send("Login must not be empty");
  }

  const allowed_chars = /[^\p{L}\p{Nd}]/u;
  if (body.login.match(allowed_chars)) {
    resp.status(422);
    resp.send("Login field allows only unicode letters and numbers");
  }

  if (body.password == null) {
    resp.status(422);
    resp.send('Request body does not have "password" field!');
    return;
  }

  if (body.password.length < MIN_PASSWORD_LENGTH) {
    resp.status(422);
    resp.send(
      `Password should be at least ${MIN_PASSWORD_LENGTH} symbols long!`
    );
    return;
  }

  next();
}

async function getUser(login: string): Promise<UserModel> {
  return await new Promise<UserModel>((res, rej) => {
    SQL_GET_USER.get<{ login: string; password_hash: string }>(
      login,
      (err, row) => {
        if (err != null) {
          return rej(err);
        }

        if (!row) {
          return rej(`User with login ${login} does not exists!`);
        }

        return res(
          new UserModel(
            row!.login,
            HashedPassword.unsafe_raw(row!.password_hash)
          )
        );
      }
    );
  });
}

async function guardEndpoint(
  req: express.Request,
  resp: express.Response,
  next: express.NextFunction
) {
  if (!req.query.token) {
    resp.status(400);
    return resp.send("Token query parameter required!");
  }

  const token = req.query.token!.toString();
  const jwt_verify_result = await jose.jwtVerify(token, JWT_SECRET);

  // token is verified. As we are the token issuer,
  // we can trust, there login field is present
  const login = jwt_verify_result.payload.login as string;

  (req as any).login = login;

  next();
}
