import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not defined in the environment variables.");
}

export const checkAuth = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(" ")[1] || req.cookies?.token;

  if (!token) {
    res.status(401).json({ error: "Unauthorized: Token not provided" });
    return;
  }

  jwt.verify(token, JWT_SECRET, (err:any, decoded:any) => {
    if (err) {
      res.status(401).json({ error: "Unauthorized: Invalid token" });
      return;
    }
    // @ts-ignore
    req.user = decoded;
    next();
  });
};
