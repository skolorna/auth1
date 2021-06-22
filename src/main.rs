mod jwt;
mod certstore;

fn main() {
    let claims = jwt::Claims {
        sub: "user1234".to_owned(),
        company: "Skolorna".to_owned(),
        exp: 100000000000,
    };

    let token = jwt::encode(&claims).expect("failed to sign token");

    println!("{}", token);

    let decoded = jwt::decode(&token).expect("failed to verify token");

    println!("{:?}", decoded.header)
}
