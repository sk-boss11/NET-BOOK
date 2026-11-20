def register_social_models(db):

    class Post(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
        content = db.Column(db.Text, nullable=False, default="")
        media_url = db.Column(db.String(500))
        media_type = db.Column(db.String(20))
        created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)

    class FriendRequest(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
        receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
        status = db.Column(db.String(20), nullable=False, default="pending")
        created_at = db.Column(db.DateTime, server_default=db.func.now())
        __table_args__ = (
            db.UniqueConstraint("sender_id", "receiver_id"),
        )

    class Notification(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
        actor_id = db.Column(db.Integer, db.ForeignKey("user.id"))
        notification_type = db.Column(db.String(30), nullable=False)
        message = db.Column(db.String(300), nullable=False)
        is_read = db.Column(db.Boolean, nullable=False, default=False)
        created_at = db.Column(db.DateTime, server_default=db.func.now())

    class Story(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
        media_url = db.Column(db.String(500), nullable=False)
        media_type = db.Column(db.String(20), nullable=False)
        caption = db.Column(db.String(500))
        expires_at = db.Column(db.DateTime, nullable=False, index=True)
        created_at = db.Column(db.DateTime, server_default=db.func.now())

    class SocialGroup(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        creator_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
        name = db.Column(db.String(100), nullable=False)
        description = db.Column(db.Text)
        created_at = db.Column(db.DateTime, server_default=db.func.now())

    class GroupMember(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        group_id = db.Column(db.Integer, db.ForeignKey("social_group.id"), nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
        role = db.Column(db.String(20), nullable=False, default="member")
        joined_at = db.Column(db.DateTime, server_default=db.func.now())
        __table_args__ = (
            db.UniqueConstraint("group_id", "user_id"),
        )

    class Reel(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
        video_url = db.Column(db.String(1000), nullable=False)
        thumbnail_url = db.Column(db.String(1000))
        caption = db.Column(db.String(2000), nullable=False, default="")
        duration_seconds = db.Column(db.Float, nullable=False)
        width = db.Column(db.Integer, nullable=False)
        height = db.Column(db.Integer, nullable=False)
        status = db.Column(db.String(20), nullable=False, default="processing", index=True)
        created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)

    class ReelLike(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        reel_id = db.Column(db.Integer, db.ForeignKey("reel.id"), nullable=False, index=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
        created_at = db.Column(db.DateTime, server_default=db.func.now())
        __table_args__ = (db.UniqueConstraint("reel_id", "user_id"),)

    class ReelComment(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        reel_id = db.Column(db.Integer, db.ForeignKey("reel.id"), nullable=False, index=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
        content = db.Column(db.String(2000), nullable=False)
        created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)

    return Post, FriendRequest, Notification, Story, SocialGroup, GroupMember, Reel, ReelLike, ReelComment
