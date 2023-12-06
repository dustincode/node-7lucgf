const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const app = express();
const port = 3000;

import { NextFunction, Request, Response } from 'express';

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

interface FieldError {
  field: string;
  message: string;
}

const saltRounds = '10';
const username = joi.string().min(3).max(24).required();
const email = joi.string().email().required();
const type = joi.string().valid('user', 'admin').required();
const password = joi
  .string()
  .min(5)
  .max(24)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{3,}$/)
  .required();

const registerSchema = joi.object({
  username,
  email,
  type,
  password,
});

const loginSchema = joi.object({
  username,
  password,
});

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

function getUserByUsername(name: string): UserEntry | undefined {
  return MEMORY_DB[name];
}

function saveUser(username: string, user: UserEntry): void {
  MEMORY_DB[username] = user;
}

function getFieldErrors(error: any): FieldError[] {
  const fieldErrors = [];
  for (let fieldError of error.details || []) {
    fieldErrors.push({
      field: fieldError.context.key,
      message: fieldError.message,
    });
  }
  return fieldErrors;
}

function catchErrors(fn: (rq: Request, rs: Response, n: NextFunction) => any) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      return fn(req, res, next);
    } catch (error) {
      next(error);
    }
  };
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request body -> UserDto
app.post(
  '/register',
  catchErrors((req: Request, res: Response) => {
    // Validate user object using joi
    // - username (required, min 3, max 24 characters)
    // - email (required, valid email address)
    // - type (required, select dropdown with either 'user' or 'admin')
    // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)
    const {
      error,
      value: { username, password, type, email },
    } = registerSchema.validate(req.body || {}, { allowUnknown: true });

    if (error) {
      return res.status(400).json({
        code: 400,
        title: 'Bad Request',
        message: 'Request body invalid!',
        fieldErrors: getFieldErrors(error),
      });
    }

    if (getUserByUsername(username)) {
      return res.status(400).json({
        code: 409,
        title: 'Bad Request',
        message: 'Username already registered!',
      });
    }

    saveUser(username, {
      email,
      salt: saltRounds,
      type,
      passwordhash: bcrypt.hashSync(password, Number(saltRounds)),
    });

    return res.status(200).json({
      code: 200,
      message: 'Register successfully.',
    });
  })
);

// Request body -> { username: string, password: string }
// Return 200 if username and password match
// Return 401 else
app.post(
  '/login',
  catchErrors((req: Request, res: Response) => {
    const {
      error,
      value: { username, password },
    } = loginSchema.validate(req.body || {}, { allowUnknown: true });

    if (error) {
      return res.status(401).json({
        code: 401,
        title: 'Unauthorized',
        message: 'Invalid username or password!',
      });
    }

    const user = getUserByUsername(username);

    if (!user || !bcrypt.compareSync(password, user.passwordhash)) {
      return res.status(401).json({
        code: 401,
        title: 'Unauthorized',
        message: 'Invalid username or password!',
      });
    }

    return res.status(200).json({
      code: 200,
      message: 'Login successfully.',
    });
  })
);

app.use((req: Request, res: Response, next: NextFunction) => {
  const error: any = new Error(`Not found - ${req.originalUrl}`);
  error.status = 404;
  next(error);
});

app.use((error: any, req: Request, res: Response, next: NextFunction) => {
  return res.status(error.status || 500).json({
    code: error.status || 500,
    message: error.message,
  });
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
