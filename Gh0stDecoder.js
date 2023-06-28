# Copyright (c) 2014 The MITRE Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# This program has been re-written from Python to NodeJS by John-Michael Glenn

# The typical format for a Gh0st packet is:
# <flag><compressed_size><uncompressed_size><zlib payload>
#
# - flag is a 5 character string
# - compressed size is the size of the entire packet, not just zlib payload
# - uncompressed size of zlib payload
# - zlib payload consists of zlib header ('\x78\x9c') and compressed payload

const { unzipSync } = require("node:zlib");

const tokens = {
	"\u0000": command_actived,
	"\u0001": command_list_drive,
	"\u0002": command_list_files,
	"\u0003": command_down_files,
	"\u0004": command_file_size,
	"\u0005": command_file_data,
	"\u0006": command_exception,
	"\u0007": command_continue,
	"\b": command_stop,
	"\t": command_delete_file,
	"\n": command_delete_directory,
	"\u000b": command_set_transfer_mode,
	"\f": command_create_folder,
	"\r": command_rename_file,
	"\u000e": command_open_file_show,
	"\u000f": command_open_file_hide,
	"\u0010": command_screen_spy,
	"\u0011": command_screen_reset,
	"\u0012": command_algorithm_reset,
	"\u0013": command_screen_ctrl_alt_del,
	"\u0014": command_screen_control,
	"\u0015": command_screen_block_input,
	"\u0016": command_screen_blank,
	"\u0017": command_screen_capture_layer,
	"\u0018": command_screen_get_clipboard,
	"\u0019": command_screen_set_clipboard,
	"\u001a": command_webcam,
	"\u001b": command_webcam_enablecompress,
	"\u001c": command_webcam_disablecompress,
	"\u001d": command_webcam_resize,
	"\u001e": command_next,
	"\u001f": command_keyboard,
	" ": command_keyboard_offline,
	"!": command_keyboard_clear,
	"\"": command_audio,
	"#": command_system,
	"$": command_pslist,
	"%": command_wslist,
	"&": command_dialupass,
	"'": command_killprocess,
	"(": command_shell,
	")": command_session,
	"*": command_remove,
	"+": command_down_exec,
	",": command_update_server,
	"-": command_clean_event,
	".": command_open_url_hide,
	"/": command_open_url_show,
	"0": command_rename_remark,
	"1": command_replay_heartbeat,
	"d": token_auth,
	"e": token_heartbeat,
	"f": token_login,
	"g": token_drive_list,
	"h": token_file_list,
	"i": token_file_size,
	"j": token_file_data,
	"k": token_transfer_finish,
	"l": token_delete_finish,
	"m": token_get_transfer_mode,
	"n": token_get_filedata,
	"o": token_createfolder_finish,
	"p": token_data_continue,
	"q": token_rename_finish,
	"r": token_exception,
	"s": token_bitmapinfo,
	"t": token_firstscreen,
	"u": token_nextscreen,
	"v": token_clipboard_text,
	"w": token_webcam_bitmapinfo,
	"x": token_webcam_dib,
	"y": token_audio_start,
	"z": token_audio_data,
	"{": token_keyboard_start,
	"|": token_keyboard_data,
	"}": token_pslist,
	"~": token_wslist,
	"\u007f": token_dialupass,
	"\u0080": token_shell_start
};

const status = 1;

function decode_Gh0st(msg) {
	const b = msg.subarray(0, 1);
	if (!tokens[b]) {
		return {
			status: 0,
			message: `Unknown token: 0x${b.toString("hex")}\n${msg.toString("hex")}`
		};
	}
	tokens[b](msg.subarray(1));
}

function command_actived(msg) {
	//console.log("COMMAND: ACTIVED");
	return { status, message: "COMMAND: ACTIVED" };
}

function command_list_drive(msg) {
	//console.log("COMMAND: LIST DRIVE");
	return { status, message: "COMMAND: LIST DRIVE" };
}

function command_list_files(msg) {
	//console.log(`COMMAND: LIST FILES (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: LIST FILES (${msg.subarray(0, -1).toString()})` };
}

function command_down_files(msg) {
	//console.log(`COMMAND: DOWN FILES (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: DOWN FILES (${msg.subarray(0, -1).toString()})` };
}

function command_file_size(msg) {
	const [fname, size] = get_name_and_size(msg);
	//console.log(`COMMAND: FILE SIZE (${fname}: ${size})`);
	return { status, message: `COMMAND: FILE SIZE (${fname}: ${size})` };
}

function command_file_data(msg) {
	//console.log(`COMMAND: FILE DATA (${msg.subarray(8).byteLength})`);
	return { status, message: `COMMAND: FILE DATA (${msg.subarray(8).byteLength})` };
}

function command_exception(msg) {
	//console.log("command_exception");
	//console.log(msg.toString("hex"));
	return { status, message: `command_exception\n${msg.toString("hex")}` };
}

function command_continue(msg) {
	//console.log("COMMAND: CONTINUE");
	return { status, message: "COMMAND: CONTINUE" };
}

function command_stop(msg) {
	//console.log("COMMAND: STOP");
	return { status, message: "COMMAND: STOP" };
}

function command_delete_file(msg) {
	//console.log(`COMMAND: DELETE FILE (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: DELETE FILE (${msg.subarray(0, -1).toString()})` };
}

function command_delete_directory(msg) {
	//console.log(`COMMAND: DELETE DIRECTORY (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: DELETE DIRECTORY (${msg.subarray(0, -1).toString()})` };
}

function command_set_transfer_mode(msg) {
	// Mode
	let mode;
	switch (msg.readUInt32LE()) {
		case 0:
			mode = "NORMAL";
			break;
		case 1:
			mode = "ADDITION";
			break;
		case 2:
			mode = "ADDITION ALL";
			break;
		case 3:
			mode = "OVERWRITE";
			break;
		case 4:
			mode = "OVERWRITE ALL";
			break;
		case 5:
			mode = "JUMP";
			break;
		case 6:
			mode = "JUMP ALL";
			break;
		case 7:
			mode = "CANCEL";
			break;
		default:
			mode = "UNKNOWN";
	}
	//console.log(`COMMAND: SET TRANSFER MODE (${mode})`);
	return { status, message: `COMMAND: SET TRANSFER MODE (${mode})` };
}

function command_create_folder(msg) {
	//console.log(`COMMAND: CREATE FOLDER (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: CREATE FOLDER (${msg.subarray(0, -1).toString()})` };
}

function command_rename_file(msg) {
	const nullIndex = msg.indexOf("\u0000");
	//console.log(`COMMAND: RENAME FILE (${msg.subarray(0, nullIndex).toString()} -> ${msg.subarray(nullIndex + 1).toString()})`);
	return { status, message: `COMMAND: RENAME FILE (${msg.subarray(0, nullIndex).toString()} -> ${msg.subarray(nullIndex + 1).toString()})` };
}

function command_open_file_show(msg) {
	//console.log(`COMMAND: OPEN FILE SHOW (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: OPEN FILE SHOW (${msg.subarray(0, -1).toString()})` };
}

function command_open_file_hide(msg) {
	//console.log(`COMMAND: OPEN FILE HIDE (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: OPEN FILE HIDE (${msg.subarray(0, -1).toString()})` };
}

function command_screen_spy(msg) {
	//console.log("COMMAND: SCREEN SPY");
	return { status, message: "COMMAND: SCREEN SPY" };
}

function command_screen_reset(msg) {
	//console.log(`COMMAND: SCREEN RESET (${msg.readUInt8()})`);
	return { status, message: `COMMAND: SCREEN RESET (${msg.readUInt8()})` };
}

function command_algorithm_reset(msg) {
	//console.log(`COMMAND: ALGORITHM RESET (${msg.readUInt8()})`);
	return { status, message: `COMMAND: ALGORITHM RESET (${msg.readUInt8()})` };
}

function command_screen_ctrl_alt_del(msg) {
	//console.log("COMMAND: SEND CTRL ALT DEL");
	return { status, message: "COMMAND: SEND CTRL ALT DEL" };
}

function command_screen_control(msg) {
	//console.log("COMMAND: SCREEN CONTROL");
	return { status, message: "COMMAND: SCREEN CONTROL" };
}

function command_screen_block_input(msg) {
	//console.log(`COMMAND: SCREEN BLOCK INPUT (${msg.readUInt8() === 0 ? "OFF" : "ON"})`);
	return { status, message: `COMMAND: SCREEN BLOCK INPUT (${msg.readUInt8() === 0 ? "OFF" : "ON"})` };
}

function command_screen_blank(msg) {
	//console.log(`COMMAND: SCREEN BLANK (${msg.readUInt8() === 0 ? "OFF" : "ON"})`);
	return { status, message: `COMMAND: SCREEN BLANK (${msg.readUInt8() === 0 ? "OFF" : "ON"})` };
}

function command_screen_capture_layer(msg) {
	//console.log(`COMMAND: SCREEN CAPTURE LAYER (${msg.readUInt8() === 0 ? "OFF" : "ON"})`);
	return { status, message: `COMMAND: SCREEN CAPTURE LAYER (${msg.readUInt8() === 0 ? "OFF" : "ON"})` };
}

function command_screen_get_clipboard(msg) {
	//console.log("COMMAND: SCREEN GET CLIPBOARD");
	//console.log(msg.subarray(0, -1).toString());
	return { status, message: `COMMAND: SCREEN GET CLIPBOARD\n${msg.subarray(0, -1).toString()}` };
}

function command_screen_set_clipboard(msg) {
	//console.log("COMMAND: SCREEN SET CLIPBOARD");
	//console.log(msg.subarray(0, -1).toString());
	return { status, message: `COMMAND: SCREEN SET CLIPBOARD\n${msg.subarray(0, -1).toString()}` };
}

function command_webcam(msg) {
	//console.log("COMMAND: WEBCAM");
	return { status, message: "COMMAND: WEBCAM" };
}

function command_webcam_enablecompress(msg) {
	//console.log("command_webcam_enablecompress");
	//console.log(msg.toString("hex"));
	return { status, message: `command_webcam_enablecompress\n${msg.toString("hex")}` };
}

function command_webcam_disablecompress(msg) {
	//console.log("COMMAND: WEBCAM DISABLECOMPRESS");
	return { status, message: "COMMAND: WEBCAM DISABLECOMPRESS" };
}

function command_webcam_resize(msg) {
	//console.log("command_webcam_resize");
	//console.log(msg.toString("hex"));
	return { status, message: `command_webcam_resize\n${msg.toString("hex")}` };
}

function command_next(msg) {
	//console.log("COMMAND: NEXT");
	return { status, message: "COMMAND: NEXT" };
}

function command_keyboard(msg) {
	//console.log("COMMAND: KEYBOARD");
	return { status, message: "COMMAND: KEYBOARD" };
}

function command_keyboard_offline(msg) {
	//console.log("COMMAND: KEYBOARD OFFLINE");
	return { status, message: "COMMAND: KEYBOARD OFFLINE" };
}

function command_keyboard_clear(msg) {
	//console.log("COMMAND: KEYBOARD CLEAR");
	return { status, message: "COMMAND: KEYBOARD CLEAR" };
}

function command_audio(msg) {
	//console.log("COMMAND: AUDIO");
	return { status, message: "COMMAND: AUDIO" };
}

function command_system(msg) {
	//console.log("COMMAND: SYSTEM");
	return { status, message: "COMMAND: SYSTEM" };
}

function command_pslist(msg) {
	//console.log("COMMAND: PSLIST");
	return { status, message: "COMMAND: PSLIST" };
}

function command_wslist(msg) {
	//console.log("COMMAND: WSLIST");
	return { status, message: "COMMAND: WSLIST" };
}

function command_dialupass(msg) {
	//console.log("COMMAND: DIALUPASS");
	return { status, message: "COMMAND: DIALUPASS" };
}

function command_killprocess(msg) {
	//console.log(`COMMAND: KILLPROCESS (${msg.readUInt32LE()})`);
	return { status, message: `COMMAND: KILLPROCESS (${msg.readUInt32LE()})` };
}

function command_shell(msg) {
	//console.log("COMMAND: SHELL");
	return { status, message: "COMMAND: SHELL" };
}

function command_session(msg) {
	let message;
	switch (msg.readUInt8()) {
		case 4:
			message = "LOGOFF";
			break;
		case 5:
			message = "SHUTDOWN";
			break;
		case 6:
			message = "REBOOT";
			break;
		default:
			return;
	}
	//console.log(`COMMAND: SESSION (${message})`);
	return { status, message: `COMMAND: SESSION (${message})` };
}

function command_remove(msg) {
	//console.log("COMMAND: REMOVE");
	return { status, message: "COMMAND: REMOVE" };
}

function command_down_exec(msg) {
	//console.log(`COMMAND: DOWN EXEC (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: DOWN EXEC (${msg.subarray(0, -1).toString()})` };
}

function command_update_server(msg) {
	//console.log(`COMMAND: UPDATE SERVER (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: UPDATE SERVER (${msg.subarray(0, -1).toString()})` };
}

function command_clean_event(msg) {
	//console.log("COMMAND: CLEAN EVENT");
	return { status, message: "COMMAND: CLEAN EVENT" };
}

function command_open_url_hide(msg) {
	//console.log(`COMMAND: OPEN URL HIDE (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: OPEN URL HIDE (${msg.subarray(0, -1).toString()})` };
}

function command_open_url_show(msg) {
	//console.log(`COMMAND: OPEN URL SHOW (${msg.subarray(0, -1).toString()})`);
	return { status, message: `COMMAND: OPEN URL SHOW (${msg.subarray(0, -1).toString()})` };
}

function command_rename_remark(msg) {
	//console.log("command_rename_remark");
	//console.log(msg.toString("hex"));
	return { status, message: `command_rename_remark\n${msg.toString("hex")}` };
}

function command_replay_heartbeat(msg) {
	//console.log("command_replay_heartbeat");
	//console.log(msg.toString("hex"));
	return { status, message: `command_replay_heartbeat\n${msg.toString("hex")}` };
}

function token_auth(msg) {
	//console.log("token_auth");
	//console.log(msg.toString("hex"));
	return { status, message: `token_auth\n${msg.toString("hex")}` };
}

function token_heartbeat(msg) {
	//console.log("token_heartbeat");
	//console.log(msg.toString("hex"));
	return { status, message: `token_heartbeat\n${msg.toString("hex")}` };
}

function token_login(msg) {
	//TODO Figure out what these first 3 bytes are
	msg = msg.subarray(3);
	const osver_size = msg.readUInt32LE(),
				major = msg.readUInt32LE(4),
				minor = msg.readUInt32LE(8),
				build = msg.readUInt32LE(12);
	let buf = msg.subarray(osver_size);
	msg = msg.subarray(20);
	let nullIndex = msg.indexOf("\u0000");
	let sp = msg.subarray(0, nullIndex);

	if (sp.length === 0) {
		sp = "No service pack";
	}

	msg = msg.subarray(132);
	const suite_mask = msg.readUInt16LE(),
				product_type = msg.readUInt8(2);
	msg = msg.subarray(4);
	let os = `UNKNOWN OS (${major}.${minor} SM: ${suite_mask} PT: ${product_type})`;

	if (major === 5) {
		if (minor === 0) {
			os = "Windows 2000";
		} else if (minor === 1) {
			os = "Windows XP";
		} else if (minor === 2) {
			if (product_type === 1) {
				os = "Windows XP";
			} else {
				if (suite_mask & 32768) {
					os = "Windows Home Server";
				} else {
					os = "Windows Server 2003";
				}
			}
		}
	} else {
		if (major === 6) {
			if (minor === 0) {
				if (product_type === 1) {
					os = "Windows Vista";
				} else {
					os = "Windows Server 2008";
				}
			} else if (minor === 1) {
				if (product_type === 1) {
					os = "Windows 7";
				} else {
					os = "Windows Server 2008 R2";
				}
			} else if (minor === 2) {
				if (product_type === 1) {
					os = "Windows 8";
				} else {
					os = "Windows Server 2012";
				}
			}
		}
	}

	let token = "TOKEN: LOGIN";
	if (msg.length !== 64) {
		token = "TOKEN: LOGIN (IP AND WEBCAM MAY BE WRONG)";
	}

	const clock = buf.readUInt32LE(),
				ip = [buf.readUInt8(4),buf.readUInt8(5),buf.readUInt8(6),buf.readUInt8(7)].join(".")
	buf = buf.subarray(8);
	nullIndex = buf.indexOf("\u0000");
	const hostname = buf.subarray(0, nullIndex);
	buf = buf.subarray(50);

	// The webcam field is a bool. In my sample this is 2 bytes. May not
	// always be true depending upon compiler.
	let webcam = "no";
	if (buf.readUInt16LE()) {
		webcam = "yes";
	}

	//console.log(`${token} - ${hostname}: ${os} ${sp} - Build: ${build} - Clock: ${clock} Mhz - IP: ${ip} Webcam: ${webcam}`);
	return { status, message: `${token} - ${hostname}: ${os} ${sp} - Build: ${build} - Clock: ${clock} Mhz - IP: ${ip} Webcam: ${webcam}` };
}

function token_drive_list(msg) {
	let desc, drive, free, fs, nullIndex, total,
			message = "TOKEN: DRIVE LIST\nDRIVE\tTOTAL\tFREE\tFILESYSTEM\tDESCRIPTION";
	//console.log("TOKEN: DRIVE LIST");
	//console.log("DRIVE\tTOTAL\tFREE\tFILESYSTEM\tDESCRIPTION");

	while (msg.length > 9) {
		drive = msg[0].toString();
		msg = msg.subarray(2);
		total = msg.readUInt32LE();
		free = msg.readUInt32LE(1);
		msg = msg.subarray(8);
		nullIndex = msg.indexOf("\u0000");
		desc = msg.subarray(0, nullIndex);
		msg = msg.subarray(nullIndex + 1);
		nullIndex = msg.indexOf("\u0000");
		fs = msg.subarray(0, nullIndex);
		//console.log(`${drive}\t${total}\t${free}\t${fs}\t${desc}`);
		message += `\n${drive}\t${total}\t${free}\t${fs}\t${desc}`;
		msg = msg.subarray(nullIndex + 1);
	}

	return { status, message };
}

function token_file_list(msg) {
	let message = "TOKEN: FILE LIST (INVALID HANDLE)";
	if (msg.length === 0) {
		//console.log("TOKEN: FILE LIST (INVALID HANDLE)");
		return { status: 0, message };
	}

	//console.log("TOKEN: FILE LIST");
	//console.log("TYPE\tNAME\tSIZE\tWRITE TIME");
	message = `TOKEN: FILE LIST\nTYPE\tNAME\tSIZE\tWRITE TIME`;

	let d, hsize, lsize, size, name, nullIndex, wtime;

	while (msg.length >= 1) {
		d = msg.readUInt8(1);

		if (d & 16) {
			d = "DIR";
		} else {
			d = "FILE";
		}

		msg = msg.subarray(1);
		nullIndex = msg.find("\u0000");
		name = msg.subarray(0, nullIndex);
		msg = msg.subarray(nullIndex + 1);
		hsize = msg.readUInt32LE();
		lsize = msg.readUInt32LE(4);
		wtime = msg.readUInt64LE(8);
		size = winsizeize(hsize, lsize);
		msg = msg.subarray(16);
		//console.log(`${d}\t${name}\t${size}\t${wtime}`);
		message += `\n${d}\t${name}\t${size}\t${wtime}`;
	}

	return { status, message };
}

function token_file_size(msg) {
	const [fname, size] = get_name_and_size(msg);
	//console.log(`TOKEN: FILE SIZE (${fname}: ${size})`);
	return { status, message: `TOKEN: FILE SIZE (${fname}: ${size})` };
}

function token_file_data(msg) {
	//console.log(`TOKEN: FILE DATA (${msg.subarray(8).byteLength})`);
	return { status, message: `TOKEN: FILE DATA (${msg.subarray(8).byteLength})` };
}

function token_transfer_finish(msg) {
	//console.log("TOKEN: TRANSFER FINISH");
	return { status, message: "TOKEN: TRANSFER FINISH" };
}

function token_delete_finish(msg) {
	//console.log("TOKEN: DELETE FINISH");
	return { status, message: "TOKEN: DELETE FINISH" };
}

function token_get_transfer_mode(msg) {
	//console.log("TOKEN: GET TRANSFER MODE");
	return { status, message: "TOKEN: GET TRANSFER MODE" };
}

function token_get_filedata(msg) {
	//console.log("token_get_filedata");
	//console.log(msg.toString("hex"));
	return { status, message: `token_get_filedata\n${msg.toString("hex")}` };
}

function token_createfolder_finish(msg) {
	//console.log("TOKEN: CREATEFOLDER FINISH");
	return { status, message: "TOKEN: CREATEFOLDER FINISH" };
}

function token_data_continue(msg) {
	//console.log("TOKEN: DATA CONTINUE");
	return { status, message: "TOKEN: DATA CONTINUE" };
}

function token_rename_finish(msg) {
	//console.log("TOKEN: RENAME FINISH");
	return { status, message: "TOKEN: RENAME FINISH" };
}

function token_exception(msg) {
	//console.log("token_exception");
	//console.log(msg.toString("hex"));
	return { status, message: `token_exception\n${msg.toString("hex")}` };
}

function token_bitmapinfo(msg) {
	//console.log("TOKEN: BITMAPINFO");
	return { status, message: "TOKEN: BITMAPINFO" };
}

function token_firstscreen(msg) {
	//console.log("TOKEN: FIRST SCREEN");
	return { status, message: "TOKEN: FIRST SCREEN" };
}

function token_nextscreen(msg) {
	//console.log("TOKEN: NEXT SCREEN");
	return { status, message: "TOKEN: NEXT SCREEN" };
}

function token_clipboard_text(msg) {
	//console.log("TOKEN: CLIPBOARD TEXT");
	//console.log(msg.subarray(0, -1).toString("hex"));
	return { status, message: `TOKEN: CLIPBOARD TEXT\n${msg.subarray(0, -1).toString("hex")}` };
}

function token_webcam_bitmapinfo(msg) {
	//console.log("TOKEN: WEBCAM BITMAP INFO");
	return { status, message: "TOKEN: WEBCAM BITMAP INFO" };
}

function token_webcam_dib(msg) {
	//console.log("TOKEN: WEBCAM DIB");
	return { status, message: "TOKEN: WEBCAM DIB" };
}

function token_audio_start(msg) {
	//console.log("TOKEN: AUDIO START");
	return { status, message: "TOKEN: AUDIO START" };
}

function token_audio_data(msg) {
	//console.log("TOKEN: AUDIO DATA");
	return { status, message: "TOKEN: AUDIO DATA" };
}

function token_keyboard_start(msg) {
	//console.log(`TOKEN: KEYBOARD START (${msg.readUInt8() === 0 ? "OFFLINE" : "ONLINE"})`);
	return { status, message: `TOKEN: KEYBOARD START (${msg.readUInt8() === 0 ? "OFFLINE" : "ONLINE"})` };
}

function token_keyboard_data(msg) {
	//console.log("TOKEN: KEYBOARD DATA");
	//console.log(msg);
	return { status, message: `TOKEN: KEYBOARD DATA\n${msg.toString()}` };
}

function token_pslist(msg) {
	let exe, name, nullIndex, pid,
			message = `TOKEN: PSLIST\nPID\tEXE\t\tPROCE NAME`;
	//console.log("TOKEN: PSLIST");
	//console.log("PID\tEXE\t\tPROC NAME");

	while (msg.length >= 4) {
		pid = msg.readUInt32LE();
		msg = msg.subarray(4);
		nullIndex = msg.indexOf("\u0000");
		exe = msg.subarray(0, nullIndex);
		msg = msg.subarray(nullIndex + 1);
		nullIndex = msg.indexOf("\u0000");
		name = msg.subarray(0, nullIndex);
		msg = msg.subarray(nullIndex + 1);
		//console.log(`${pid}\t${exe}\t\t${name}`);
		message += `\n${pid}\t${exe}\t\t${name}`;
	}

	return { status, message };
}

function token_wslist(msg) {
	let nullIndex, pid, title,
			message = `TOKEN: WSLIST\nPID\tTITLE`;
	//console.log("TOKEN: WSLIST");
	//console.log("PID\tTITLE");

	while (msg.length >= 4) {
		pid = msg.readUInt32LE();
		msg = msg.subarray(4);
		nullIndex = msg.indexOf("\u0000");
		title = msg.subarray(0, nullIndex);
		msg = msg.subarray(nullIndex + 1);
		//console.log(`${pid}\t${title}`);
		message += `\n${pid}\t${title}`;
	}

	return { status, message };
}

function token_dialupass(msg) {
	//console.log("TOKEN: DIALUPASS");
	return { status, message: "TOKEN: DIALUPASS" };
}

function token_shell_start(msg) {
	//console.log("TOKEN: SHELL START");
	return { status, message: "TOKEN: SHELL START" };
}

function get_name_and_size(msg) {
	const hsize = msg.readUInt32LE(),
				lsize = msg.readUInt32LE(4);
	return [msg.subarray(8, -1), winsizeize(hsize, lsize)];
}

function winsizeize(hsize, lsize) {
	return (hsize * (0xffffffff + 1)) + lsize;
}

module.exports = exports = { decode_Gh0st };