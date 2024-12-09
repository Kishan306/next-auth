import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { db } from "./db";
import { compare } from "bcrypt";

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(db),
  secret: process.env.NEXTAUTH_SECRET,
  session: {
    strategy: "jwt",
  },
  pages: {
    signIn: "/sign-in",
    newUser: "/sign-up"
  },
  providers: [
    CredentialsProvider({
      name: "Credentials",

      credentials: {
        email: { label: "email", type: "email", placeholder: "john@email.com" },
        password: { label: "password", type: "password" },
      },
      async authorize(credentials, req) {
        // Add logic here to look up the user from the credentials supplied
        if(!credentials?.email || !credentials?.password){
          return null;
        }

        //check if user with that email exists in database
        const existingUser = await db.user.findUnique({
          where: {
            email: credentials.email
          }
        });

        //if user with email doesn't exist, return null
        if(!existingUser){
          return null;
        }

        //match passwords for verification
        const passwordMatch = await compare(credentials.password, existingUser.password);

        //if password doesn't match, return null
        if(!passwordMatch){
          return null;
        }

        //with both the above conditions satisfied, return userdata
        //(id should be in string format, otherwise it gives an error)
        return {
          id: existingUser.id,
          username: existingUser.username,
          email: existingUser.email
        }
      },
    }),
  ],
  callbacks: {
    async jwt({token, user }){
      if(user){
        return {
          ...token, 
          username: user.username
        }
      }
      return token
    },
    async session({ session, user, token }){
      return {
        ...session,
        user: {
          ...session.user,
          username: token.username
        }
      }
    }
  }
};
