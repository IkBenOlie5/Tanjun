import tanjun
from examples import protos

complex_component = tanjun.Component()


@complex_component.with_command
@tanjun.with_guild_check
@tanjun.as_message_command("guild")
async def guild_command(
    ctx: tanjun.traits.MessageContext, database: protos.DatabaseProto = tanjun.injected(type=protos.DatabaseProto)
):
    assert ctx.guild_id is not None  # This is checked by the "with_guild_check"
    guild_info = await database.get_guild_info(ctx.guild_id)

    if not guild_info:
        # CommandError's message will be sent as a response message.
        raise tanjun.CommandError("No information stored for the current guild")

    ...  # TODO: implement response


@complex_component.with_command
@tanjun.as_message_command_group("user")
async def user(
    ctx: tanjun.traits.MessageContext, database: protos.DatabaseProto = tanjun.injected(type=protos.DatabaseProto)
) -> None:
    user = await database.get_user_info(ctx.author.id)

    if not user:
        # CommandError's message will be sent as a response message.
        raise tanjun.CommandError("No information stored for you")

    ...  # TODO: implement response


@user.with_command
@tanjun.as_message_command("remove self")
async def remove_self(
    ctx: tanjun.traits.MessageContext, database: protos.DatabaseProto = tanjun.injected(type=protos.DatabaseProto)
) -> None:
    await database.remove_user(ctx.author.id)


# Here we define a loader which can be used to easily load this example
# components into a bot from a link (assuming the environment has all the
# right configurations setup.)
@tanjun.as_loader
def load_examples(client: tanjun.traits.Client) -> None:
    client.add_component(complex_component.copy())
