import express, { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import { signInSchema, LoginSchema } from "./validator";
import { checkAuth } from "./checkAuth";
dotenv.config();
import cookieParser from "cookie-parser";

const app = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not defined in the environment variables.");
}

app.post("/signin", async (req: Request, res: Response) => {
  try {
    const validated = signInSchema.safeParse(req.body);

    if (!validated.success) {
      console.error("Validation error during signup:", validated.error.errors);
      res.status(400).json({
        error: "Invalid input data",
        details: validated.error.errors,
      });
      return;
    }

    const { email, password } = validated.data;

    const hashedPassword = await bcrypt.hash(password, 10);

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      console.error(`Signup error: User with email ${email} already exists`);
      res.status(409).json({ error: "User already exists" });
      return;
    }

    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res
      .status(201)
      .cookie("token", token, { httpOnly: true })
      .json({ message: "User created successfully" });
  } catch (error) {
    console.error("Unexpected error during signup:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", async (req: Request, res: Response) => {
  try {
    const validated = LoginSchema.safeParse(req.body);

    if (!validated.success) {
      console.error("Validation error during signin:", validated.error.errors);
      res.status(400).json({
        error: "Invalid input data",
        details: validated.error.errors,
      });
      return;
    }

    const { email, password } = validated.data;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      console.error(`Signin error: No user found with email ${email}`);
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      console.error(`Signin error: Invalid password for email ${email}`);
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res
      .cookie("token", token, { httpOnly: true })
      .json({ message: "Login successful" });
  } catch (error) {
    console.error("Unexpected error during signin:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// test route
app.get("/test", (req: Request, res: Response) => {
  res.json({ message: "Test route is working!" });
});

// protected route
app.get("/me", checkAuth, async (req: Request, res: Response) => {
  //@ts-ignore
  const userId = req.user.userId;

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  const filteredUser = {
    ...user,
    password: "Nah, you can't see this!",
  };

  console.log("User data:", filteredUser);
  res.status(200).json({ filteredUser });
});

const PORT = 4000;

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
