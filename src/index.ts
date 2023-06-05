/* eslint-disable turbo/no-undeclared-env-vars */
import express, { Request, Response, Express } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

import { expireTime, CORS, PORT } from "./constants";
import { generateRandomHexString } from "./crypto";

dotenv.config()

const SECRET_KEY = process.env.SECRET_KEY;
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY;

if (!SECRET_KEY || !REFRESH_SECRET_KEY) {
  console.error("Secret keys are not defined in environment variables");
  process.exit(1);
}

const SERVER: Express = express();
SERVER.use(express.json());
SERVER.use(CORS);
 
export interface UserData {
  id: string;
  username: string;
  email: string;
  password: string;
}

export interface UserDataWithoutPassword{
  id: string;
  username:string;
  email:string;
}

export interface Post {
  id: string;
  porductType: string;
  pricePerUnit: number;
  units: number;
  seller: string;
  location: string;
}

export interface Transaction {
  seller: string;
  buyer: string;
  postId: string;
  verificationCode: string;
  post: Post; // Added post property
}




export const usersById: Map<string, UserData> = new Map();
export const usersByEmail: Map<string, string> = new Map();
export const usersByUsername: Map<string, string> = new Map();
export let refreshTokens: Array<string> = [];



export const posts: Map<string, Post> = new Map<string, Post>();

const postsByUser: Map<string, Array<string>> = new Map<string, Array<string>>();



export const transactions: Map<string, Transaction> = new Map<string, Transaction>();
export const transactionsByUser = new Map<string, Transaction[]>();


export function registerUser(user: UserData) {
  usersById.set(user.id, user);
  usersByEmail.set(user.email, user.id);
  usersByUsername.set(user.username, user.id);
}

export function addRefreshToken(refreshToken: string) {
  refreshTokens.push(refreshToken);
}

function addPost(post: Post, user: UserData) {
  
  post.seller = user.username;
  
  const postId = uuidv4();
  post.id = postId; 


  posts.set(postId, post);

  const postsOfUser: Array<string>|undefined = postsByUser.get(user.id);
  if(postsOfUser){
    postsOfUser.push(postId);
    postsByUser.set(user.id, postsOfUser)
  }
  else{
    postsByUser.set(user.id, [postId])
  }
}

function removePost(postId: string) {
  if (posts.has(postId)) {
    posts.delete(postId);
    for (const [userId, userPosts] of postsByUser) {
      const updatedUserPosts = userPosts.filter((postIdParam) => postIdParam !== postId);
      postsByUser.set(userId, updatedUserPosts);
    }
    return true;
  }
  return false;
}

function editPost(postId: string, updatedPost: Post) {
  if (posts.has(postId)) {
    posts.set(postId, updatedPost);
    return true;
  }
  return false;
}



function getPostsAsArrayWithId() {
  const postsArray = Array.from(posts.entries());
  const postsData = postsArray.map(([id, post]) => ({ postId: id, ...post }));
  return postsData;
}

function addTransaction(postId: string, buyer: string): boolean {
  const post = posts.get(postId);

  if (post) {
    const postRemoved = removePost(postId);

    if (postRemoved) {
      const verificationCode = generateRandomHexString(64);

      const transaction: Transaction = {
        seller: post.seller,
        buyer,
        postId,
        verificationCode,
        post,
      };

      // Update transactions map
      transactions.set(postId, transaction);

      // Update transactionsByUser map for buyer
      const userTransactions = transactionsByUser.get(buyer) || [];
      userTransactions.push(transaction);
      transactionsByUser.set(buyer, userTransactions);

      // Update transactionsByUser map for seller
      const sellerTransactions = transactionsByUser.get(post.seller) || [];
      sellerTransactions.push(transaction);
      transactionsByUser.set(post.seller, sellerTransactions);

      return true;
    }
  }

  return false;
}



function getVerificationCode(postId: string, participantId: string): string | undefined {
  const transaction = transactions.get(postId);

  if (transaction && (transaction.buyer === participantId || transaction.seller === participantId)) {
    return transaction.verificationCode;
  }

  return undefined;
}





export function updateUserData(oldUserData: UserData, username: string | undefined, email: string | undefined, password: string | undefined) {
  const { id } = oldUserData;
  const { username: oldUsername, email: oldEmail } = oldUserData;

  let newUserData: UserData = oldUserData;

  // Update the Maps if username or email has changed
  if (username) {
    if (oldUsername !== username) {
      usersByUsername.delete(oldUsername);
      usersByUsername.set(username, id);
    }
    newUserData.username = username;
  }
  if (email) {
    if (oldEmail !== email) {
      usersByEmail.delete(oldEmail);
      usersByEmail.set(email, id);
    }
    newUserData.email = email;
  }
  
  if (password) {
    newUserData.password = password;
  }

  usersById.set(id, newUserData);
}

export function isUsernameTaken(username: string) {
  return usersByUsername.has(username);
}

export function isEmailTaken(email: string) {
  return usersByEmail.has(email);
}


const authenticateToken = (req: Request, res: Response, next: any) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    req.body.user = user;
    next();
  });
};

SERVER.get("/users", (req: Request, res: Response) => {
  res.status(200).json(Array.from(usersById.values()).map(({password, ...rest}) => rest));
});

SERVER.post("/users/register", async (req: Request, res: Response) => {
  console.log("REGISTER")
  const { username, email, password } = req.body;

  if (!(username && email && password)) {
    return res.status(400).send("Missing username, email, or password");
  }

  if (isUsernameTaken(username)) {
    return res.status(400).send("Username is already taken");
  }

  if (isEmailTaken(email)) {
    return res.status(400).send("Email is already registered");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user: UserData = { id: uuidv4(), username, email, password: hashedPassword };
    registerUser(user);
    res.status(201).send();
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
});

SERVER.post("/users/login", async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!(username && password)) {
    return res.status(400).send("Missing username or password");
  }

  const userId = usersByUsername.get(username);
  const user = userId ? usersById.get(userId) : undefined;

  if (user === undefined) {
    return res.status(400).send("Cannot find the user");
  }

  try {
    if (await bcrypt.compare(password, user.password)) {
      const { password, ...userWithoutPassword } = user;
      const accessToken = jwt.sign(userWithoutPassword, SECRET_KEY, { expiresIn: expireTime });
      const refreshToken = jwt.sign(userWithoutPassword, REFRESH_SECRET_KEY);
      addRefreshToken(refreshToken);
      res.json({ accessToken, refreshToken });
    } else {
      res.send("Failed Login");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
});

SERVER.post("/token", (req, res) => {
  const { token: refreshToken } = req.body;

  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err: any, user: any) => {
    if (err) return res.sendStatus(403);
    const { id, username, email } = user;
    const accessToken = jwt.sign({ id, username, email }, SECRET_KEY, { expiresIn: expireTime });
    res.json({ accessToken });
  });
});

SERVER.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token);
  res.sendStatus(204);
});

SERVER.put("/users/me", authenticateToken, async (req: Request, res: Response) => {
  const { username, email, password } = req.body;
  const { id } = req.body.user;

  if (!id) {
    return res.status(400).send("Missing user id");
  }

  const oldUserData = usersById.get(id);

  if (oldUserData) {
    if (username && oldUserData.username !== username && isUsernameTaken(username)) {
      return res.status(400).send("Username is already taken");
    }
    if (email && oldUserData.email !== email && isEmailTaken(email)) {
      return res.status(400).send("Email is already registered");
    }
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateUserData(oldUserData, username, email, hashedPassword);
    } else {
      updateUserData(oldUserData, username, email, undefined);
    }
    res.status(200).send("User data updated");
  } else {
    res.status(404).send("User not found");
  }
});
SERVER.post("/products/add", authenticateToken, async (req: Request, res: Response) => {
  const { post } = req.body;
  const { id } = req.body.user;

  if (!(post && id)) {
    return res.status(400).send("Missing post data or user id");
  }

  try {
    post.id = uuidv4();
    const user = usersById.get(id);
    if (user) {
      addPost(post, user);
      res.json([...posts.values()]);
    } else {
      res.status(400).send("Invalid user id");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
});

SERVER.put("/products/edit/:postId", authenticateToken, (req: Request, res: Response) => {
  const { postId } = req.params;
  const { id: userId } = req.body.user;
  const updatedPost = req.body.post;

  if (!postId) {
    return res.status(400).send("Missing post ID");
  }

  if (!updatedPost) {
    return res.status(400).send("Missing updated post data");
  }

  const post = posts.get(postId);

  if (post) {
    if (post.seller === userId) {
      const success = editPost(postId, updatedPost);
      if (success) {
        res.status(200).json([...posts.values()]);
      } else {
        res.status(404).send("Post not found");
      }
    } else {
      res.status(403).send("Forbidden");
    }
  } else {
    res.status(404).send("Post not found");
  }
});

SERVER.delete("/products/remove/:postId", authenticateToken, (req: Request, res: Response) => {
  const { postId } = req.params;

  if (!postId) {
    return res.status(400).send("Missing post ID");
  }

  const userId = req.body.user?.id;

  if (!userId) {
    return res.status(401).send("Unauthorized");
  }

  const post = posts.get(postId);

  if (post) {
    if (post.seller === userId) {
      const success = removePost(postId);
      if (success) {
        res.sendStatus(204);
      } else {
        res.status(404).send("Post not found");
      }
    } else {
      res.status(403).send("Forbidden");
    }
  } else {
    res.status(404).send("Post not found");
  }
});


SERVER.get("/products/posts", (req: Request, res: Response) => {
  const postsData = getPostsAsArrayWithId();
  res.status(200).json(postsData);
});

SERVER.get("/users/:userId/posts", (req: Request, res: Response) => {
  const { userId } = req.params;

  if (!userId) {
    return res.status(400).send("Missing user ID");
  }

  const userPosts = postsByUser.get(userId);

  if (userPosts) {
    const userPostData = userPosts.map((postId) => {
      const post = posts.get(postId);
      return post ? { postId, ...post } : null;
    });

    const filteredUserPosts = userPostData.filter((post) => post !== null);

    res.status(200).json(filteredUserPosts);
  } else {
    res.status(404).send("User not found or has no posts");
  }
});

SERVER.get("/users/:userId/transactions", (req: Request, res: Response) => {
  const { userId } = req.params;

  if (!userId) {
    return res.status(400).send("Missing user ID");
  }

  const userTransactions = transactionsByUser.get(userId);

  if (userTransactions) {
    res.status(200).json(userTransactions);
  } else {
    res.status(404).send("User not found or has no transactions");
  }
});


SERVER.post("/transactions/add", authenticateToken, (req: Request, res: Response) => {
  const { postId } = req.body;
  const { id: buyer } = req.body.user;

  if (!postId || !buyer) {
    return res.status(400).send("Missing post ID or buyer ID");
  }

  const post = posts.get(postId);

  if (!post) {
    return res.status(404).send("Post not found");
  }

  const transactionAdded = addTransaction(postId, buyer);

  if (transactionAdded) {
    return res.status(201).send("Transaction added successfully");
  } else {
    return res.status(500).send("Failed to add transaction");
  }
});








console.log(PORT)
SERVER.listen(PORT);
