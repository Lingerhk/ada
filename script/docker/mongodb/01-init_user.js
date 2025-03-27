db = db.getSiblingDB("db_ada");
db.createUser(
        {
            user: "user_ada",
            pwd: "XEl44B4p3hFurztFMo38",
            roles: [
                {
                    role: "readWrite",
                    db: "db_ada"
                }
            ]
        }
);

