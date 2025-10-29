import {randomBytes} from 'node:crypto'
import {hashSync, verifySync} from "@node-rs/argon2"

const SALT_SIZE = 10;

export class HashedPassword {
  readonly value: string;
  private constructor(password_hash: string) {
    this.value = password_hash;
  }
  
  public static unsafe_raw(password_hash: string): HashedPassword {
    return new HashedPassword(password_hash);
  }

  public static hash_password(password: string): HashedPassword {
    return new HashedPassword(hashSync(password, {
      salt: randomBytes(SALT_SIZE)
    }))
  }
  public is_password_valid(input_password: string): boolean {
    return verifySync(this.value, input_password)
  }
}

export class UserModel {
  readonly password_hash: HashedPassword;

  constructor(public readonly login: string, password: string | HashedPassword) {
    if (typeof password == "string") {
      this.password_hash = HashedPassword.hash_password(password);
    } else {
      this.password_hash = password;
    }
  }
}


