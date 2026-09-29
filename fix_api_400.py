with open("api.py", "r") as f:
    content = f.read()

old_except = """    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))"""

new_except = """    except Exception as e:
        err_msg = str(e)
        if "Not a supported capture file" in err_msg:
            raise HTTPException(status_code=400, detail="Invalid PCAP file format. Please upload a valid .pcap or .pcapng file.")
        raise HTTPException(status_code=500, detail=err_msg)"""

content = content.replace(old_except, new_except)

with open("api.py", "w") as f:
    f.write(content)
