const db = require("./config")

function getusers() {
    return db("users")
}

async function adduser(user_object) {
    const [newuserid] = await db.insert(user_object).into("users")
    const newuser = await db.first("*").from("users").where("id", newuserid)
    return newuser
}

function findByUsername(username) {
    return db.first("*").from("users").where("username", username)
}

module.exports = {
    getusers,
    adduser,
    findByUsername,
}
